/*
 * _guardian.c — C-level integrity verifier for tethered locked mode.
 *
 * At activation, snapshots the identity (pointer) of every critical Python
 * object in the enforcement path.  On every socket audit event, re-fetches
 * each object and compares — any mismatch means tampering, and ALL network
 * access is blocked (fail-closed).
 *
 * Also owns trusted reentrancy state for DNS resolution.  The Python-side
 * _in_hook ContextVar is a convenience flag; in locked mode, the C guardian
 * verifies its value against its own thread-local counter.  A mismatch
 * means someone set the ContextVar from Python without going through the
 * trusted C path (_guardian.resolve()).
 *
 * No policy matching in C.  Zero duplication of Python logic.
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <string.h>

#ifdef _WIN32
#  include <io.h>
#  define write _write
#else
#  include <unistd.h>
#endif

/* ── Thread-local storage ───────────────────────────────────────── */

#if defined(_MSC_VER)
#  define THREAD_LOCAL __declspec(thread)
#elif defined(__GNUC__) || defined(__clang__)
#  define THREAD_LOCAL __thread
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L \
      && !defined(__STDC_NO_THREADS__)
#  define THREAD_LOCAL _Thread_local
#else
#  define THREAD_LOCAL  /* fallback: not thread-safe, but still functional */
#endif

/* ── Snapshot entry ──────────────────────────────────────────────── */

typedef struct {
    PyObject *owner;         /* object to call getattr on (module or class) */
    PyObject *attr_name_obj; /* strong ref — owns the char* lifetime */
    const char *attr_name;   /* UTF-8 pointer into attr_name_obj */
    PyObject *expected;      /* pointer stored at activation */
    int check_code;          /* also verify __code__ identity? */
    PyObject *expected_code; /* __code__ pointer at activation */
} SnapshotEntry;

/* ── Atomics compat ──────────────────────────────────────────────── */

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L \
    && !defined(__STDC_NO_ATOMICS__)
#  include <stdatomic.h>
#  define ATOMIC_INT     _Atomic int
#  define ATOMIC_STORE(v, x) atomic_store(&(v), (x))
#  define ATOMIC_LOAD(v)     atomic_load(&(v))
#elif defined(_MSC_VER)
#  include <intrin.h>
#  define ATOMIC_INT     volatile int
#  define ATOMIC_STORE(v, x) _InterlockedExchange((volatile long *)&(v), (x))
#  define ATOMIC_LOAD(v)     _InterlockedOr((volatile long *)&(v), 0)
#else
   /* GCC/Clang built-ins */
#  define ATOMIC_INT     volatile int
#  define ATOMIC_STORE(v, x) __atomic_store_n(&(v), (x), __ATOMIC_SEQ_CST)
#  define ATOMIC_LOAD(v)     __atomic_load_n(&(v), __ATOMIC_SEQ_CST)
#endif

/* ── C-level state ───────────────────────────────────────────────── */

static ATOMIC_INT       guardian_active = 0;
static PyObject        *guardian_config = NULL;    /* strong ref to _Config */
static unsigned long long guardian_token_id = 0;
static ATOMIC_INT       tamper_alerted = 0;
static PyObject        *core_module = NULL;
static PyObject        *egress_blocked_cls = NULL; /* strong ref */

/* Cached ContextVar object (strong ref) */
static PyObject        *in_hook_var = NULL;        /* _in_hook ContextVar */

/* Cached _socket module for resolve() */
static PyObject        *csocket_module = NULL;

/* Cached __code__ objects for caller verification of resolve() (strong refs).
 * Slot 0: _handle_getaddrinfo (the audit-hook DNS path).
 * Slot 1: _fallback_resolve   (the connect-time re-resolution path used to
 *                              repair DNS divergence under gevent +
 *                              load-balanced services).
 * NULL slots are skipped — fail closed if every slot is NULL. */
#define EXPECTED_CALLER_COUNT 2
static PyObject        *expected_caller_codes[EXPECTED_CALLER_COUNT] = { NULL, NULL };
static const char      *expected_caller_names[EXPECTED_CALLER_COUNT] = {
    "_handle_getaddrinfo",
    "_fallback_resolve",
};

/* Thread-local trusted reentrancy counter for DNS resolution.
 * Invisible to Python — only C functions can modify it. */
static THREAD_LOCAL int resolving_depth = 0;

/*
 * Static array — never freed, so a racing thread that slipped past the
 * guardian_active check reads zeroed-but-valid memory (fail-closed) rather
 * than freed heap memory (undefined behavior).  128 entries is generous;
 * the current snapshot uses ~28.
 */
#define MAX_SNAPSHOT 128
static SnapshotEntry    snapshot[MAX_SNAPSHOT];
static int              snapshot_count = 0;

/* ── Tamper alert ────────────────────────────────────────────────── */

static void
write_tamper_alert(void)
{
    if (ATOMIC_LOAD(tamper_alerted)) return;
    ATOMIC_STORE(tamper_alerted, 1);
    const char *msg =
        "[tethered] TAMPER DETECTED: locked policy integrity violated — "
        "all network access is now blocked.\n";
    (void)write(2, msg, (unsigned int)strlen(msg));
}

/* ── Raise EgressBlocked ─────────────────────────────────────────── */

static int
raise_blocked(const char *host)
{
    if (egress_blocked_cls != NULL) {
        PyObject *exc = PyObject_CallFunction(
            egress_blocked_cls, "sO", host, Py_None);
        if (exc != NULL) {
            PyErr_SetObject(egress_blocked_cls, exc);
            Py_DECREF(exc);
        }
    }
    if (!PyErr_Occurred())
        PyErr_Format(PyExc_RuntimeError,
                     "Blocked by tethered (integrity violation): %s", host);
    return -1;
}

/* Helper: raise EgressBlocked from a Python-callable function (returns NULL). */
static PyObject *
raise_blocked_py(const char *desc)
{
    write_tamper_alert();
    if (egress_blocked_cls != NULL) {
        PyObject *exc = PyObject_CallFunction(
            egress_blocked_cls, "sO", desc, Py_None);
        if (exc != NULL) {
            PyErr_SetObject(egress_blocked_cls, exc);
            Py_DECREF(exc);
        }
    }
    if (!PyErr_Occurred())
        PyErr_Format(PyExc_RuntimeError,
                     "Blocked by tethered (integrity violation): %s", desc);
    return NULL;
}

/* ── Integrity verification ──────────────────────────────────────── */

static int
verify_integrity(void)
{
    /* Check _config identity */
    if (core_module != NULL) {
        PyObject *current = PyObject_GetAttrString(core_module, "_config");
        if (current != NULL) {
            int same = (current == guardian_config);
            Py_DECREF(current);
            if (!same) return 0;
        } else {
            PyErr_Clear();
            return 0; /* _config not accessible — treat as tampered */
        }
    }

    /*
     * Check all snapshot entries.
     *
     * Read count once — on free-threaded builds (PEP 703) clear_snapshot()
     * may race and zero snapshot_count while we iterate.  A stale count
     * just means we visit entries that have been Py_CLEAR'd; the NULL
     * guard below makes that fail-closed rather than a crash.
     */
    int n = snapshot_count;
    for (int i = 0; i < n; i++) {
        SnapshotEntry *e = &snapshot[i];

        /* Defensive: owner may be NULL if clear_snapshot() raced us
         * (free-threaded Python).  Treat as tampered → fail-closed. */
        if (e->owner == NULL)
            return 0;

        PyObject *current = PyObject_GetAttrString(e->owner, e->attr_name);
        if (current == NULL) {
            PyErr_Clear();
            return 0; /* attribute removed — tampered */
        }
        int ok = (current == e->expected);
        if (ok && e->check_code) {
            PyObject *code = PyObject_GetAttrString(current, "__code__");
            if (code == NULL) {
                PyErr_Clear();
                ok = 0;
            } else {
                ok = (code == e->expected_code);
                Py_DECREF(code);
            }
        }
        Py_DECREF(current);
        if (!ok) return 0;
    }

    return 1; /* integrity intact */
}

/* ── ContextVar consistency check ───────────────────────────────── */

/*
 * Verify that the _in_hook ContextVar matches C-owned trusted state.
 *
 * _in_hook should only be True when resolving_depth > 0 (i.e., we are
 * inside _guardian.resolve()).  Only relevant for socket events.
 *
 * Returns 1 if consistent, 0 if tampered.
 */
static int
check_contextvar_consistency(int is_socket)
{
    /* Use PyContextVar_Get (direct C API) instead of PyObject_CallMethod —
     * this is the audit-event hot path, and method dispatch through Python
     * adds measurable overhead.  The ContextVar carries a registered default
     * of False, so passing NULL for default_value yields a strong reference
     * to the default when the var is unset in this context. */
    if (is_socket && in_hook_var != NULL) {
        PyObject *val = NULL;
        if (PyContextVar_Get(in_hook_var, NULL, &val) == 0 && val != NULL) {
            int is_true = PyObject_IsTrue(val);
            Py_DECREF(val);
            if (is_true && resolving_depth == 0)
                return 0; /* _in_hook True without C-owned resolution */
        } else {
            PyErr_Clear();
        }
    }

    return 1; /* consistent */
}

/* ── Subprocess event check ──────────────────────────────────────── */

static int
is_subprocess_event(const char *event)
{
    return (strcmp(event, "subprocess.Popen") == 0 ||
            strcmp(event, "os.system") == 0 ||
            strcmp(event, "os.exec") == 0 ||
            strcmp(event, "os.posix_spawn") == 0 ||
            strcmp(event, "os.spawn") == 0 ||
            strcmp(event, "os.startfile") == 0);
}

/* ── The C audit hook ────────────────────────────────────────────── */

static int
guardian_hook(const char *event, PyObject *args, void *userData)
{
    (void)userData;

    if (!ATOMIC_LOAD(guardian_active))
        return 0;

    int is_socket = (strncmp(event, "socket.", 7) == 0);
    if (!is_socket && !is_subprocess_event(event))
        return 0;

    /* Fast path: legitimate recursion from our own resolve() */
    if (is_socket && resolving_depth > 0)
        return 0;

    /* Check ContextVar consistency BEFORE integrity check.
     * Detects _in_hook.set(True) without corresponding C-owned trusted state. */
    if (!check_contextvar_consistency(is_socket)) {
        write_tamper_alert();

        const char *host = "unknown (ContextVar tamper)";
        if (PyTuple_Check(args) && PyTuple_GET_SIZE(args) >= 1) {
            PyObject *h = PyTuple_GET_ITEM(args, 0);
            if (PyUnicode_Check(h)) {
                const char *s = PyUnicode_AsUTF8(h);
                if (s) host = s;
            }
        }
        return raise_blocked(host);
    }

    if (verify_integrity())
        return 0; /* All good — Python hook handles enforcement */

    /* TAMPER DETECTED — block ALL network/subprocess access */
    write_tamper_alert();

    /* Extract context for the error message */
    const char *host = "unknown";
    if (PyTuple_Check(args) && PyTuple_GET_SIZE(args) >= 1) {
        PyObject *h = PyTuple_GET_ITEM(args, 0);
        if (is_socket &&
            (strcmp(event, "socket.connect") == 0 ||
             strcmp(event, "socket.sendto") == 0 ||
             strcmp(event, "socket.sendmsg") == 0)) {
            if (PyTuple_GET_SIZE(args) >= 2) {
                PyObject *addr = PyTuple_GET_ITEM(args, 1);
                if (PyTuple_Check(addr) && PyTuple_GET_SIZE(addr) >= 1)
                    h = PyTuple_GET_ITEM(addr, 0);
            }
        }
        if (PyUnicode_Check(h)) {
            const char *s = PyUnicode_AsUTF8(h);
            if (s) host = s;
        }
    }

    return raise_blocked(host);
}

/* ── Snapshot management ─────────────────────────────────────────── */

static void
clear_snapshot(void)
{
    for (int i = 0; i < snapshot_count; i++) {
        Py_CLEAR(snapshot[i].owner);
        Py_CLEAR(snapshot[i].attr_name_obj);
        Py_CLEAR(snapshot[i].expected);
        Py_CLEAR(snapshot[i].expected_code);
    }
    snapshot_count = 0;
}

/*
 * Build a new snapshot from items_list (tuples: (owner, attr_name, check_code)).
 * Uses a staging area so the old snapshot is preserved if building fails —
 * this keeps the guardian in a valid fail-closed state during re-activation.
 */
static int
build_snapshot(PyObject *items_list)
{
    SnapshotEntry staging[MAX_SNAPSHOT];
    int staging_count = 0;

    if (!PyList_Check(items_list)) {
        PyErr_SetString(PyExc_TypeError, "snapshot must be a list");
        return -1;
    }

    Py_ssize_t n = PyList_GET_SIZE(items_list);
    if (n > MAX_SNAPSHOT) {
        PyErr_Format(PyExc_ValueError,
                     "too many snapshot entries (%zd, max %d)", n, MAX_SNAPSHOT);
        return -1;
    }

    for (Py_ssize_t i = 0; i < n; i++) {
        PyObject *item = PyList_GET_ITEM(items_list, i);
        PyObject *owner, *attr_name_obj;
        int check_code;

        if (!PyArg_ParseTuple(item, "OUp", &owner, &attr_name_obj, &check_code))
            goto fail;

        const char *attr_name = PyUnicode_AsUTF8(attr_name_obj);
        if (!attr_name) goto fail;

        PyObject *current = PyObject_GetAttrString(owner, attr_name);
        if (current == NULL) goto fail;

        PyObject *code = NULL;
        if (check_code) {
            code = PyObject_GetAttrString(current, "__code__");
            if (code == NULL) {
                Py_DECREF(current);
                goto fail;
            }
        }

        SnapshotEntry *e = &staging[staging_count++];
        Py_INCREF(owner);
        e->owner = owner;
        Py_INCREF(attr_name_obj);
        e->attr_name_obj = attr_name_obj; /* strong ref — owns the char* */
        e->attr_name = attr_name;         /* UTF-8 pointer into attr_name_obj */
        e->expected = current;            /* steal reference */
        e->check_code = check_code;
        e->expected_code = code;          /* steal reference (may be NULL) */
    }

    /* Success — commit: swap staging into the live snapshot */
    clear_snapshot();
    memcpy(snapshot, staging, sizeof(SnapshotEntry) * staging_count);
    snapshot_count = staging_count;
    return 0;

fail:
    /* Clean up staging without touching the live snapshot */
    for (int j = 0; j < staging_count; j++) {
        Py_CLEAR(staging[j].owner);
        Py_CLEAR(staging[j].attr_name_obj);
        Py_CLEAR(staging[j].expected);
        Py_CLEAR(staging[j].expected_code);
    }
    return -1;
}

/* ── Helper: cache a function's __code__ from core_module ────────── */

static PyObject *
cache_func_code(const char *func_name)
{
    PyObject *func = PyObject_GetAttrString(core_module, func_name);
    if (func == NULL) return NULL;
    PyObject *code = PyObject_GetAttrString(func, "__code__");
    Py_DECREF(func);
    return code; /* caller owns the reference; may be NULL on error */
}

/* ── Python-callable functions ───────────────────────────────────── */

static PyObject *
py_activate(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *config;
    PyObject *exc_class;
    unsigned long long token_id;
    PyObject *snapshot_items;

    if (!PyArg_ParseTuple(args, "OOKO",
                          &config, &exc_class, &token_id, &snapshot_items))
        return NULL;

    /* If guardian is already active, verify the token before replacing */
    if (ATOMIC_LOAD(guardian_active) && token_id != guardian_token_id) {
        PyErr_SetString(PyExc_RuntimeError,
            "tethered: replacing locked guardian requires correct lock_token");
        return NULL;
    }

    /* Build integrity snapshot */
    if (build_snapshot(snapshot_items) < 0)
        return NULL;

    Py_XDECREF(guardian_config);
    Py_INCREF(config);
    guardian_config = config;

    Py_XDECREF(egress_blocked_cls);
    Py_INCREF(exc_class);
    egress_blocked_cls = exc_class;

    guardian_token_id = token_id;
    ATOMIC_STORE(tamper_alerted, 0);
    ATOMIC_STORE(guardian_active, 1);

    /* Cache tethered._core */
    if (core_module == NULL) {
        core_module = PyImport_ImportModule("tethered._core");
        if (core_module == NULL)
            return NULL;
    }

    /* Cache _socket module for resolve() */
    if (csocket_module == NULL) {
        csocket_module = PyImport_ImportModule("_socket");
        if (csocket_module == NULL)
            return NULL;
    }

    /* Cache ContextVar object */
    Py_XDECREF(in_hook_var);
    in_hook_var = PyObject_GetAttrString(core_module, "_in_hook");
    if (in_hook_var == NULL) { PyErr_Clear(); }

    /* Cache expected __code__ objects for caller verification of resolve(). */
    for (int i = 0; i < EXPECTED_CALLER_COUNT; i++) {
        Py_XDECREF(expected_caller_codes[i]);
        expected_caller_codes[i] = cache_func_code(expected_caller_names[i]);
        if (expected_caller_codes[i] == NULL) {
            /* Best-effort: a missing helper means that path can't be
             * authorized.  PyErr is cleared so activate() doesn't fault;
             * resolve() will fail closed for the missing slot. */
            PyErr_Clear();
        }
    }

    /* Install audit hook once */
    static int hook_installed = 0;
    if (!hook_installed) {
        if (PySys_AddAuditHook(guardian_hook, NULL) < 0)
            return NULL;
        hook_installed = 1;
    }

    Py_RETURN_NONE;
}

static PyObject *
py_deactivate(PyObject *self, PyObject *args)
{
    (void)self;
    unsigned long long token_id;

    if (!PyArg_ParseTuple(args, "K", &token_id))
        return NULL;

    if (!ATOMIC_LOAD(guardian_active))
        Py_RETURN_NONE;

    if (token_id != guardian_token_id) {
        PyErr_SetString(PyExc_RuntimeError,
            "tethered: guardian deactivation requires correct lock_token");
        return NULL;
    }

    ATOMIC_STORE(guardian_active, 0);
    clear_snapshot();
    Py_CLEAR(guardian_config);
    Py_CLEAR(egress_blocked_cls);
    Py_CLEAR(in_hook_var);
    for (int i = 0; i < EXPECTED_CALLER_COUNT; i++) {
        Py_CLEAR(expected_caller_codes[i]);
    }
    /* csocket_module kept alive — harmless, avoids re-import */
    guardian_token_id = 0;
    ATOMIC_STORE(tamper_alerted, 0);

    Py_RETURN_NONE;
}

static PyObject *
py_is_active(PyObject *self, PyObject *Py_UNUSED(ignored))
{
    (void)self;
    return PyBool_FromLong(ATOMIC_LOAD(guardian_active));
}

static PyObject *
py_check_token(PyObject *self, PyObject *args)
{
    (void)self;
    unsigned long long token_id;
    if (!PyArg_ParseTuple(args, "K", &token_id))
        return NULL;
    if (!ATOMIC_LOAD(guardian_active))
        Py_RETURN_TRUE;
    return PyBool_FromLong(token_id == guardian_token_id);
}

/* ── C-guarded DNS resolution ───────────────────────────────────── */

/*
 * resolve(host, port, family, type, proto, flags) → list
 *
 * Wraps _socket.getaddrinfo with a C-internal resolving_depth counter
 * that the guardian hook trusts.  When the guardian is active, also
 * verifies that the caller is _handle_getaddrinfo (frame __code__ check).
 */
static PyObject *
py_resolve(PyObject *self, PyObject *args)
{
    (void)self;
    PyObject *host, *port;
    int family = 0, socktype = 0, proto = 0, flags = 0;

    if (!PyArg_ParseTuple(args, "OOiiii",
                          &host, &port, &family, &socktype, &proto, &flags))
        return NULL;

    /* Caller verification: only the cached authorized callers
     * (_handle_getaddrinfo and _fallback_resolve) may call this.
     * Fail closed if no Python frame is available — a missing frame means
     * the caller is non-Python (e.g. a C extension) and cannot be verified,
     * so we cannot grant trust.  All-NULL slots also fail closed (no
     * authorized caller registered → resolve unavailable). */
    if (ATOMIC_LOAD(guardian_active)) {
        PyFrameObject *frame = PyEval_GetFrame();
        if (frame == NULL)
            return raise_blocked_py("unauthorized _guardian.resolve() call");
        PyCodeObject *code = PyFrame_GetCode(frame);  /* strong ref */
        int valid = 0;
        for (int i = 0; i < EXPECTED_CALLER_COUNT; i++) {
            PyObject *expected = expected_caller_codes[i];
            if (expected != NULL && (PyObject *)code == expected) {
                valid = 1;
                break;
            }
        }
        Py_DECREF(code);
        if (!valid)
            return raise_blocked_py("unauthorized _guardian.resolve() call");
    }

    if (csocket_module == NULL) {
        PyErr_SetString(PyExc_RuntimeError,
            "tethered: _guardian not activated (no _socket module)");
        return NULL;
    }

    resolving_depth++;
    PyObject *result = PyObject_CallMethod(
        csocket_module, "getaddrinfo", "OOiiii",
        host, port, family, socktype, proto, flags);
    resolving_depth--;

    return result;
}

/* ── Module definition ───────────────────────────────────────────── */

static PyMethodDef guardian_methods[] = {
    {"activate",    py_activate,    METH_VARARGS,
     "Activate with config, exception class, token, and integrity snapshot."},
    {"deactivate",  py_deactivate,  METH_VARARGS,
     "Deactivate (requires correct token_id)."},
    {"is_active",   py_is_active,   METH_NOARGS,
     "Return True if the guardian is active."},
    {"check_token", py_check_token, METH_VARARGS,
     "Return True if token_id matches."},
    {"resolve",     py_resolve,     METH_VARARGS,
     "C-guarded DNS resolution with caller verification."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef guardian_module = {
    PyModuleDef_HEAD_INIT,
    "tethered._guardian",
    "C-level integrity verifier for tethered locked mode.\n\n"
    "Snapshots identity of all critical Python objects at activation.\n"
    "On tamper detection, blocks ALL network access (fail-closed).\n"
    "Owns trusted reentrancy state for DNS resolution.",
    -1,
    guardian_methods
};

PyMODINIT_FUNC
PyInit__guardian(void)
{
    return PyModule_Create(&guardian_module);
}
