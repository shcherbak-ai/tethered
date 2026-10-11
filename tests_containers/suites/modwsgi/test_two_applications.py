"""Apache with mod_wsgi, several applications: a locked policy belongs to the process.

mod_wsgi gives each application group an interpreter of its own in the
process that serves it, and creates that interpreter when the group gets its
first request there, unless the configuration has the script imported when
the process starts.  tethered's lock is one per process.  The interpreter
that calls ``activate(locked=True)`` first holds it; an interpreter created
while it is held joins it during its own startup and gets the holder's
policy; an interpreter that already existed is outside the lock and is
refused every connection, lookup and launch for as long as the lock is held.

So what counts is the order in which the interpreters of a process come into
being, and this module goes through the ways a configuration decides it:

- a daemon process group per application: nothing is shared (works);
- one process, both scripts imported at process start: the order of the
  directives decides (works when the script that locks is first);
- one process, scripts imported at the first request: the order of the
  requests decides, and when two first requests overlap, one application is
  left outside the lock (the limit, asserted as it is; a process with one
  thread cannot have it);
- one process, the lock taken before any application is loaded, by a script
  imported into the main interpreter at process start or by a launcher that
  activates and then starts Apache: every application group joins, whenever
  it is loaded (works).

Then two things that are not about the lock: unlocked policies in one
process share the variable that hands a policy to child processes, and
``%{GLOBAL}`` next to other groups, where mod_wsgi does not always run a
request in the interpreter it names.

One application per process is in ``test_one_application.py``.
"""

from __future__ import annotations

import re
import signal
import sys
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any

import pytest
from apache import EVENT_ONE, EVENT_PROXY, Site, ask, restart_gracefully, standing
from expect import (
    AT_ALLOWED,
    AT_ALLOWED_OTHER_PORT,
    EGRESS_BLOCKED,
    LOCKED_ELSEWHERE,
    NO_LAUNCHES,
    NO_OP,
    OUTSIDE_THE_LOCK,
    POLICY_DIFFERS,
    RUNTIME_ERROR,
    SUBPROCESS_BLOCKED,
    TETHERED_LOCKED,
    enforces,
    has_no_network,
    is_unrestricted,
    reached,
    refused,
)
from harness import (
    ALLOWED_NAME,
    ALLOWED_PORT,
    FORBIDDEN_NAME,
    OTHER_PORT,
    SUITE_DIR,
    Response,
    Server,
    arrivals,
    probe_path,
    reset_arrivals,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

#: ``allowed.test:9002``: the allow list of an application with a policy of its own.
OTHER_ALLOW = [f"{ALLOWED_NAME}:{OTHER_PORT}"]
LOCKED = {"activate": "locked"}
PLAIN_APP: dict[str, Any] = {}
GLOBAL = "%{GLOBAL}"
#: ``at_startup`` of an interpreter that joined a lock: it had the policy before its script ran.
JOINED_AT_STARTUP = {"tethered_imported": True, "active": True, "locked": True}
#: Whether a %{GLOBAL} request follows its worker thread into the subinterpreter that the
#: thread served before (TestGlobalNextToOtherGroups).  Observed from Python 3.12 on.
MISROUTES = sys.version_info >= (3, 12)


def start_apps(
    apps: Mapping[str, Mapping[str, Any]],
    *,
    daemon: str = "processes=1 threads=4",
    extra: str = "",
    also: Mapping[str, Mapping[str, Any]] | None = None,
    groups: Mapping[str, str] | None = None,
    embedded: bool = False,
    **start: Any,
) -> Server:
    """Start Apache with every application of ``apps`` at ``/<name>``, all in one process.

    Each application is in the application group of its name (``groups``
    names another one).  In daemon mode they share the daemon process group
    ``apps``, whose options are ``daemon``; with ``embedded`` they share
    Apache's one child process.  ``also`` are scripts that are written but
    not mounted, and ``extra`` are further directives, in which ``{name}``
    stands for the path of a script.  ``start`` goes to ``Site.start``.
    """
    site = Site()
    scripts = {name: site.script(name, **settings) for name, settings in apps.items()}
    unmounted = {name: site.script(name, **settings) for name, settings in (also or {}).items()}
    lines = [] if embedded else ["WSGIRestrictEmbedded On", f"WSGIDaemonProcess apps {daemon}"]
    for name, script in scripts.items():
        lines += [f"WSGIScriptAlias /{name} {script}", f"<Location /{name}>"]
        if not embedded:
            lines.append("    WSGIProcessGroup apps")
        lines += [f"    WSGIApplicationGroup {(groups or {}).get(name, name)}", "</Location>"]
    lines.append(extra.format(**scripts, **unmounted))
    mpm_settings = EVENT_ONE if embedded else EVENT_PROXY
    return site.start("\n".join(lines), mpm_settings=mpm_settings, **start)


def imported_at_start(name: str, group: str | None = None) -> str:
    """``WSGIImportScript`` of the script ``name`` into its group, in the process group ``apps``.

    For the ``extra`` of ``start_apps``, which puts the path of the script in.
    """
    # The braces of %{GLOBAL} are not a placeholder.
    into = (group or name).replace("{", "{{").replace("}", "}}")
    return f"WSGIImportScript {{{name}}} process-group=apps application-group={into}\n"


def together(server: Server, paths: list[str]) -> dict[str, Response]:
    """GET every path at the same moment, each on a thread of its own."""
    barrier = threading.Barrier(len(paths))

    def get(path: str) -> Response:
        barrier.wait()
        return server.get(path, timeout=60.0)

    with ThreadPoolExecutor(len(paths)) as pool:
        return dict(zip(paths, pool.map(get, paths), strict=True))


def whoami(server: Server, name: str) -> dict[str, Any]:
    return ask(server, f"/{name}", "whoami")


def outside_the_lock(me: dict[str, Any]) -> bool:
    """Whether ``activate()`` told this application that it is outside the lock."""
    activation = me["activation"]
    return (
        activation["outcome"] == "raised"
        and activation["exception"] == TETHERED_LOCKED
        and OUTSIDE_THE_LOCK in activation["message"]
        and not me["active"]
    )


# ── A daemon process group per application ────────────────────────────

EACH_ITS_OWN = """
    WSGIRestrictEmbedded On
    WSGIDaemonProcess shop processes=2 threads=1
    WSGIDaemonProcess blog processes=2 threads=1
    WSGIScriptAlias /shop {shop}
    <Location /shop>
        WSGIProcessGroup shop
    </Location>
    WSGIScriptAlias /blog {blog}
    <Location /blog>
        WSGIProcessGroup blog
    </Location>
"""


@pytest.fixture(scope="class", params=["plain", "locked"])
def policy(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(scope="class")
def each_its_own(policy: str) -> Server:
    """The shop allows ``allowed.test:9001`` and the blog ``allowed.test:9002``."""
    site = Site()
    shop = site.script("shop", activate=policy)
    blog = site.script("blog", activate=policy, allow=OTHER_ALLOW)
    return site.start(EACH_ITS_OWN.format(shop=shop, blog=blog))


class TestADaemonProcessGroupEach:
    def test_each_application_has_its_own_processes_and_its_own_policy(
        self, each_its_own: Server, policy: str
    ) -> None:
        processes = {}
        for name in ("shop", "blog"):
            processes[name] = each_its_own.each_worker(f"/{name}/whoami", 2)
            for me in processes[name].values():
                assert me["process_group"] == name, me
                assert me["activation"] == {"outcome": "activated"}, me
                assert standing(me) == ("holder" if policy == "locked" else "unlocked"), me
        assert not set(processes["shop"]) & set(processes["blog"])

    def test_each_application_enforces_its_own_allow_list(self, each_its_own: Server) -> None:
        enforces(each_its_own, "/shop")
        enforces(each_its_own, "/blog", port=OTHER_PORT, other_port=ALLOWED_PORT)

    def test_no_process_reaches_what_only_the_other_application_allows(
        self, each_its_own: Server
    ) -> None:
        for name, port in (("shop", OTHER_PORT), ("blog", ALLOWED_PORT)):
            path = f"/{name}" + probe_path("connect", ALLOWED_NAME, port)
            for report in each_its_own.each_worker(path, 2).values():
                refused(report)
        assert arrivals() == {}

    def test_a_python_child_inherits_the_policy_of_its_application(
        self, each_its_own: Server
    ) -> None:
        for name, own, other in (
            ("shop", ALLOWED_PORT, OTHER_PORT),
            ("blog", OTHER_PORT, ALLOWED_PORT),
        ):
            reached(ask(each_its_own, f"/{name}", "child", ALLOWED_NAME, own)["child"])
            refused(ask(each_its_own, f"/{name}", "child", ALLOWED_NAME, other)["child"])
        assert arrivals() == {AT_ALLOWED: 1, AT_ALLOWED_OTHER_PORT: 1}

    def test_the_processes_of_a_graceful_restart_enforce_them_too(
        self, each_its_own: Server
    ) -> None:
        first = {name: each_its_own.each_worker(f"/{name}/whoami", 2) for name in ("shop", "blog")}
        each_its_own.send_signal(signal.SIGUSR1)
        for name, port in (("shop", OTHER_PORT), ("blog", ALLOWED_PORT)):
            path = f"/{name}" + probe_path("connect", ALLOWED_NAME, port)
            for report in each_its_own.each_worker(path, 2, exclude=first[name]).values():
                refused(report)
        assert arrivals() == {}
        enforces(each_its_own, "/shop")
        enforces(each_its_own, "/blog", port=OTHER_PORT, other_port=ALLOWED_PORT)


# ── One process, both scripts imported when it starts ─────────────────

TWO_PROCESSES = "processes=2 threads=1"


def assert_shop_holds_and_blog_joined(server: Server, exclude: Any = ()) -> dict[int, Any]:
    """In every process the shop holds the lock and the blog joined it at its startup.

    Returns the blog's report from each process.
    """
    shops = server.each_worker("/shop/whoami", 2, exclude=exclude)
    blogs = server.each_worker("/blog/whoami", 2, exclude=exclude)
    assert set(shops) == set(blogs)
    for shop in shops.values():
        assert standing(shop) == "holder", shop
    for blog in blogs.values():
        assert standing(blog) == "joined", blog
        # The blog had the policy before its script ran: from tethered's bootstrap.
        assert blog["at_startup"] == JOINED_AT_STARTUP, blog
    enforces(server, "/shop")
    enforces(server, "/blog")
    return blogs


class TestBothImportedAtProcessStart:
    @pytest.mark.parametrize(
        "blog",
        [
            pytest.param(LOCKED, id="the-blog-locks-the-same-policy"),
            pytest.param(PLAIN_APP, id="the-blog-never-imports-tethered"),
        ],
    )
    def test_the_first_script_takes_the_lock_and_the_second_joins(
        self, blog: dict[str, Any]
    ) -> None:
        server = start_apps(
            {"shop": LOCKED, "blog": blog},
            daemon=TWO_PROCESSES,
            extra=imported_at_start("shop") + imported_at_start("blog"),
        )
        # Both scripts ran before the first request, in the order of the directives.
        assert server.log.count("mw_app: shop: script imported") == 2
        assert server.log.count("mw_app: blog: script imported") == 2
        first = assert_shop_holds_and_blog_joined(server)
        for me in first.values():
            expected = "activated" if blog else "not asked"
            assert me["activation"] == {"outcome": expected}, me
        if blog:
            # The blog's own activate(locked=True) with the same policy changed nothing.
            server.wait_log(NO_OP)
            # And the processes of a graceful restart come up the same way.
            server.send_signal(signal.SIGUSR1)
            assert_shop_holds_and_blog_joined(server, exclude=first)

    def test_wsgiscriptalias_with_both_groups_imports_at_process_start_too(self) -> None:
        # mod_wsgi imports a script at process start when WSGIScriptAlias names
        # its process group and its application group.
        site = Site()
        shop = site.script("shop", activate="locked")
        blog = site.script("blog")
        server = site.start(f"""
            WSGIRestrictEmbedded On
            WSGIDaemonProcess apps {TWO_PROCESSES}
            WSGIScriptAlias /shop {shop} process-group=apps application-group=shop
            WSGIScriptAlias /blog {blog} process-group=apps application-group=blog
        """)
        assert server.log.count("mw_app: shop: script imported") == 2
        assert server.log.count("mw_app: blog: script imported") == 2
        assert_shop_holds_and_blog_joined(server)

    def test_a_script_imported_before_the_lock_is_taken_has_no_network(self) -> None:
        """Limit: imported in the other order, the application that does not lock is cut off.

        The blog's interpreter exists when the shop takes the lock, so it is
        outside the lock: every connection is refused, the allowed host and
        loopback included, and so is every launch.  The blog never imported
        tethered, so what it gets is a ``RuntimeError`` from the C extension.
        It happens in every process and again after a restart: the order of
        the two directives is all that differs from the test above.
        """
        server = start_apps(
            {"shop": LOCKED, "blog": PLAIN_APP},
            daemon=TWO_PROCESSES,
            extra=imported_at_start("blog") + imported_at_start("shop"),
        )
        first = self.assert_the_blog_is_cut_off(server)
        server.send_signal(signal.SIGUSR1)
        self.assert_the_blog_is_cut_off(server, exclude=first)

    @staticmethod
    def assert_the_blog_is_cut_off(server: Server, exclude: Any = ()) -> dict[int, Any]:
        reset_arrivals()
        path = "/blog" + probe_path("connect", ALLOWED_NAME, ALLOWED_PORT)
        blogs = server.each_worker(path, 2, exclude=exclude)
        for report in blogs.values():
            assert report["outcome"] == "error", report
            assert report["exception"] == RUNTIME_ERROR, report
            assert LOCKED_ELSEWHERE in report["message"], report
            assert report["tethered_imported"] is False, report
        assert arrivals() == {}
        has_no_network(server, "/blog", RUNTIME_ERROR)
        launch = ask(server, "/blog", "child", FORBIDDEN_NAME, OTHER_PORT)
        assert launch["exception"] == RUNTIME_ERROR, launch
        assert launch["message"] == f"Blocked by tethered: subprocess.Popen {NO_LAUNCHES}", launch
        for me in server.each_worker("/shop/whoami", 2, exclude=exclude).values():
            assert standing(me) == "holder", me
        enforces(server, "/shop")
        return blogs

    def test_a_second_application_with_another_locked_policy_runs_under_the_first(
        self,
    ) -> None:
        # One locked policy per process: the blog's own is refused, and if the
        # blog goes on regardless, it is the shop's policy that it runs under.
        server = start_apps(
            {"shop": LOCKED, "blog": {"activate": "locked", "allow": OTHER_ALLOW}},
            extra=imported_at_start("shop") + imported_at_start("blog"),
        )
        blog = whoami(server, "blog")
        assert blog["activation"]["exception"] == TETHERED_LOCKED, blog
        assert POLICY_DIFFERS in blog["activation"]["message"], blog
        assert standing(blog) == "joined", blog
        enforces(server, "/shop")
        enforces(server, "/blog")


# ── One process, scripts imported at the first request ────────────────

#: Both scripts wait, before they activate, until the interpreters of both groups exist
#: (the main interpreter is the third): the first requests then overlap for certain.
OVERLAPPING = {"activate": "locked", "wait_for_interpreters": 3}
OVERLAP: dict[str, dict[str, Any]] = {"daemon": {}, "embedded": {"embedded": True}}
if sys.version_info >= (3, 13):
    # An interpreter per group with a GIL of its own.  Python 3.11 has no such thing, and
    # on 3.12 a daemon process with this directive died as soon as a second group loaded
    # this application, tethered or no tethered (32 of 32 starts), so there is nothing to
    # say about tethered there.
    OVERLAP["own-gil"] = {"extra": "WSGIPerInterpreterGIL On\n"}


def first_requests_together(server: Server) -> tuple[str, str]:
    """Send the first requests of the shop and the blog at once: (the holder, the other)."""
    replies = together(server, ["/shop/whoami", "/blog/whoami"])
    assert {reply.status for reply in replies.values()} == {200}, replies
    reports = {path.split("/")[1]: reply.json() for path, reply in replies.items()}
    for me in reports.values():
        # Each script saw both groups' interpreters before it went on to activate().
        assert me["waited"] == {"wanted": 3, "seen": 3}, me
    holders = [name for name, me in reports.items() if standing(me) == "holder"]
    assert len(holders) == 1, reports
    (other,) = set(reports) - set(holders)
    return holders[0], other


class TestImportedAtTheFirstRequest:
    def test_first_requests_one_after_the_other_the_second_application_joins(self) -> None:
        server = start_apps({"shop": LOCKED, "blog": LOCKED})
        shop = whoami(server, "shop")
        blog = whoami(server, "blog")
        assert shop["pid"] == blog["pid"]
        assert shop["interpreter"] != blog["interpreter"]
        assert standing(shop) == "holder", shop
        assert standing(blog) == "joined", blog
        assert blog["at_startup"]["locked"] is True, blog
        assert blog["activation"] == {"outcome": "activated"}, blog
        server.wait_log(NO_OP)
        enforces(server, "/shop")
        enforces(server, "/blog")

        # Joined is not holder: the blog can neither replace nor drop the policy.
        for op, params in (("activate", {"policy": "other"}), ("deactivate", {})):
            report = ask(server, "/blog", op, **params)
            assert report["exception"] == TETHERED_LOCKED, report
            assert standing(report) == "joined", report
        enforces(server, "/blog")

    @pytest.mark.parametrize("arrangement", list(OVERLAP))
    def test_overlapping_first_requests_leave_one_application_outside_the_lock(
        self, arrangement: str
    ) -> None:
        """Limit: two groups of one process, first requests at the same moment.

        mod_wsgi creates the interpreter of each group as its request
        arrives, before either script has run.  One application takes the
        lock; the interpreter of the other already exists and cannot join.
        Its ``activate()`` raises ``TetheredLocked`` although it asks for the
        very same policy, and it has no network at all: not the allowed
        host, not loopback, no child processes.  Which application loses is
        open.  The same in embedded mode and with an own GIL per interpreter.
        """
        server = start_apps({"shop": OVERLAPPING, "blog": OVERLAPPING}, **OVERLAP[arrangement])
        holder, other = first_requests_together(server)

        me = whoami(server, other)
        assert outside_the_lock(me), me
        assert me["at_startup"]["tethered_imported"] is False, me
        has_no_network(server, f"/{other}")
        launch = ask(server, f"/{other}", "child", FORBIDDEN_NAME, OTHER_PORT)
        refused(launch, SUBPROCESS_BLOCKED)
        assert launch["message"] == f"Blocked by tethered: subprocess.Popen {NO_LAUNCHES}", launch
        # Asking again, later, changes nothing.
        again = ask(server, f"/{other}", "activate", policy="same")
        assert again["exception"] == TETHERED_LOCKED, again
        assert OUTSIDE_THE_LOCK in again["message"], again
        has_no_network(server, f"/{other}")

        enforces(server, f"/{holder}")

    def test_an_application_that_lets_the_exception_out_answers_500_from_then_on(self) -> None:
        """Limit: the application outside the lock, when its script does not catch the error.

        The import of the script fails, mod_wsgi imports it again at every
        request, and every request is a 500 with the reason in the error log.
        """
        loud = {**OVERLAPPING, "catch": False}
        server = start_apps({"shop": loud, "blog": loud})
        replies = together(server, ["/shop/whoami", "/blog/whoami"])
        statuses = {path.split("/")[1]: reply.status for path, reply in replies.items()}
        assert sorted(statuses.values()) == [200, 500], statuses
        holder = next(name for name, status in statuses.items() if status == 200)
        other = next(name for name, status in statuses.items() if status == 500)

        for _ in range(3):
            path = f"/{other}" + probe_path("connect", ALLOWED_NAME, ALLOWED_PORT)
            assert server.get(path).status == 500
        assert arrivals() == {}
        assert server.log.count(f"mw_app: {other}: script imported") == 4
        assert server.log.count(f"{TETHERED_LOCKED}: tethered: activate() blocked") == 4
        assert OUTSIDE_THE_LOCK in server.log
        assert standing(whoami(server, holder)) == "holder"
        enforces(server, f"/{holder}")

    def test_with_one_thread_per_process_the_first_requests_cannot_overlap(self) -> None:
        # A daemon process with one thread creates the interpreter of the
        # second group after the script of the first has run.  When every
        # application locks the same policy, that is enough: whichever came
        # first holds the lock and the other joins.  (An application that
        # does not lock is still cut off when it happens to come first.)
        server = start_apps({"shop": LOCKED, "blog": LOCKED}, daemon=TWO_PROCESSES)
        together(server, ["/shop/whoami", "/blog/whoami"] * 4)
        shops = server.each_worker("/shop/whoami", 2)
        blogs = server.each_worker("/blog/whoami", 2)
        assert set(shops) == set(blogs)
        for pid, shop in shops.items():
            assert sorted([standing(shop), standing(blogs[pid])]) == ["holder", "joined"]
            assert shop["activation"] == blogs[pid]["activation"] == {"outcome": "activated"}
        enforces(server, "/shop")
        enforces(server, "/blog")

    def test_under_a_locked_log_only_policy_the_application_outside_keeps_its_network(
        self,
    ) -> None:
        # log_only refuses no connection, in the holder or outside the lock,
        # and only the holder reports.  Launches outside the lock stay refused.
        settings = {**OVERLAPPING, "activate": "locked,log_only"}
        server = start_apps({"shop": settings, "blog": settings})
        holder, other = first_requests_together(server)
        assert outside_the_lock(whoami(server, other))

        is_unrestricted(server, f"/{other}")
        assert "tethered: blocked" not in server.log
        is_unrestricted(server, f"/{holder}")
        server.wait_log(f"tethered: blocked getaddrinfo for {FORBIDDEN_NAME}")

        reset_arrivals()
        launch = ask(server, f"/{other}", "child", FORBIDDEN_NAME, OTHER_PORT)
        refused(launch, SUBPROCESS_BLOCKED)
        assert arrivals() == {}

    def test_unarranged_first_requests_never_leave_an_application_unrestricted(self) -> None:
        # Nothing is made to overlap here: four processes get the first
        # requests of both applications as they come.  In each process one
        # application holds the lock and the other either joined it or is
        # outside it; which it is depends on timing, and neither reaches a
        # forbidden destination.
        server = start_apps({"shop": LOCKED, "blog": LOCKED}, daemon="processes=4 threads=2")
        together(server, ["/shop/whoami", "/blog/whoami"] * 4)
        shops = server.each_worker("/shop/whoami", 4)
        blogs = server.each_worker("/blog/whoami", 4)
        assert set(shops) == set(blogs)
        outcomes: Counter[str] = Counter()
        for pid, shop in shops.items():
            pair = sorted([shop, blogs[pid]], key=standing)
            assert standing(pair[0]) == "holder", pair
            if standing(pair[1]) == "joined":
                outcomes["the other application joined"] += 1
            else:
                assert outside_the_lock(pair[1]), pair
                outcomes["the other application is outside the lock"] += 1
        print(f"\n{dict(outcomes)}", end=" ")

        reset_arrivals()
        for name in ("shop", "blog"):
            path = f"/{name}" + probe_path("connect", FORBIDDEN_NAME, OTHER_PORT)
            for report in server.each_worker(path, 4).values():
                assert report["outcome"] == "blocked", report
        assert arrivals() == {}


# ── One process, the lock taken in the main interpreter when it starts ─


class TestTheLockTakenAtProcessStart:
    """A script that only locks, imported into the main interpreter of each process.

    The main interpreter is the first one of a process, so every application
    group's interpreter is created under the lock and joins it, whenever its
    first request comes.  No request is routed to ``%{GLOBAL}``.
    """

    @pytest.mark.parametrize(
        "application",
        [
            pytest.param(OVERLAPPING, id="applications-that-lock-the-same-policy"),
            pytest.param({"wait_for_interpreters": 3}, id="applications-without-tethered"),
        ],
    )
    def test_overlapping_first_requests_both_join(self, application: dict[str, Any]) -> None:
        server = start_apps(
            {"shop": application, "blog": application},
            also={"lock": LOCKED},
            extra=imported_at_start("lock", GLOBAL),
        )
        # The lock was taken before the process started to serve.
        assert "mw_app: lock: activate() returned" in server.log
        first = self.assert_both_join(server)
        if application is OVERLAPPING:
            # Their own activate(locked=True) with the same policy changed nothing.
            assert len(re.findall(NO_OP, server.log)) == 2
        else:
            # And in the process that a graceful restart starts.
            restart_gracefully(server)
            assert self.assert_both_join(server) != first

    @staticmethod
    def assert_both_join(server: Server) -> int:
        """Overlapping first requests: both applications joined.  Returns the process."""
        replies = together(server, ["/shop/whoami", "/blog/whoami"])
        assert {reply.status for reply in replies.values()} == {200}, replies
        reports = [reply.json() for reply in replies.values()]
        for me in reports:
            assert me["waited"] == {"wanted": 3, "seen": 3}, me
            assert me["main_interpreter"] is False, me
            assert standing(me) == "joined", me
            assert me["at_startup"] == JOINED_AT_STARTUP, me
            assert me["activation"]["outcome"] in ("activated", "not asked"), me
        assert reports[0]["pid"] == reports[1]["pid"]
        enforces(server, "/shop")
        enforces(server, "/blog")
        return reports[0]["pid"]

    def test_in_embedded_mode_too(self) -> None:
        site = Site()
        scripts = {name: site.script(name, **OVERLAPPING) for name in ("shop", "blog")}
        lock = site.script("lock", activate="locked")
        server = site.start(
            f"""
            WSGIScriptAlias /shop {scripts["shop"]}
            <Location /shop>
                WSGIApplicationGroup shop
            </Location>
            WSGIScriptAlias /blog {scripts["blog"]}
            <Location /blog>
                WSGIApplicationGroup blog
            </Location>
            WSGIImportScript {lock} process-group={GLOBAL} application-group={GLOBAL}
            """,
            mpm_settings=EVENT_ONE,
        )
        self.assert_both_join(server)


# ── The policy set before Apache starts ───────────────────────────────


class TestThePolicySetBeforeApacheStarts:
    """``launcher.py`` activates a policy and then executes Apache.

    The policy travels in the environment, and tethered's bootstrap puts it
    in place in every interpreter that starts in a process of the server:
    the main interpreter of a daemon process when Python is initialised,
    each application group's interpreter when it is created.  The
    applications here never import tethered.
    """

    @pytest.mark.parametrize("policy", ["plain", "locked"])
    def test_every_interpreter_of_every_process_starts_under_it(self, policy: str) -> None:
        application = {"wait_for_interpreters": 3}
        server = start_apps(
            {"shop": application, "blog": application},
            launcher=[sys.executable, str(SUITE_DIR / "launcher.py")],
            env={"TETH_ACTIVATE": policy},
        )
        # Apache is not Python: the launcher's exec is reported as an external launch.
        server.wait_log(r"tethered: external subprocess launch detected: os\.exec\*")
        first = self.assert_both_start_under_the_policy(server, policy)
        if policy == "locked":
            # The environment of Apache's parent outlives a graceful restart.
            restart_gracefully(server)
            assert self.assert_both_start_under_the_policy(server, policy) != first

    @staticmethod
    def assert_both_start_under_the_policy(server: Server, policy: str) -> int:
        """Overlapping first requests: both applications have the policy.  Returns the process."""
        replies = together(server, ["/shop/whoami", "/blog/whoami"])
        assert {reply.status for reply in replies.values()} == {200}, replies
        reports = [reply.json() for reply in replies.values()]
        for me in reports:
            assert me["waited"] == {"wanted": 3, "seen": 3}, me
            assert me["main_interpreter"] is False, me
            assert me["activation"] == {"outcome": "not asked"}, me
            assert me["at_startup"] == {**JOINED_AT_STARTUP, "locked": policy == "locked"}, me
            # Under a lock the holder is the main interpreter, which serves no request.
            assert standing(me) == ("joined" if policy == "locked" else "unlocked"), me
        for mount in ("/shop", "/blog"):
            enforces(server, mount)
            child = ask(server, mount, "child", FORBIDDEN_NAME, OTHER_PORT)["child"]
            assert child["locked"] is (policy == "locked"), child
            refused(child)
        return reports[0]["pid"]


# ── Unlocked policies in one process ──────────────────────────────────


class TestUnlockedPoliciesInOneProcess:
    def test_a_child_and_a_later_interpreter_get_the_policy_activated_last(self) -> None:
        """Limit: unlocked policies of two groups share the variable that children inherit.

        Inside the process each application enforces its own allow list.  But
        ``_TETHERED_CHILD_POLICY`` is one variable of the process: the shop's
        Python child starts under the blog's policy, which was activated
        last, and reaches a port the shop forbids.  An application whose
        interpreter is created afterwards starts under that policy as well,
        without ever importing tethered.
        """
        server = start_apps(
            {
                "shop": {"activate": "plain"},
                "blog": {"activate": "plain", "allow": OTHER_ALLOW},
                "wiki": PLAIN_APP,
            }
        )
        for name in ("shop", "blog"):
            assert standing(whoami(server, name)) == "unlocked"
        enforces(server, "/shop")
        enforces(server, "/blog", port=OTHER_PORT, other_port=ALLOWED_PORT)

        reset_arrivals()
        child = ask(server, "/shop", "child", ALLOWED_NAME, OTHER_PORT)["child"]
        assert child["active"] is True and child["locked"] is False, child
        reached(child)
        assert arrivals() == {AT_ALLOWED_OTHER_PORT: 1}
        refused(ask(server, "/shop", "child", ALLOWED_NAME, ALLOWED_PORT)["child"])
        assert arrivals() == {AT_ALLOWED_OTHER_PORT: 1}

        wiki = whoami(server, "wiki")
        assert wiki["activation"] == {"outcome": "not asked"}, wiki
        assert wiki["at_startup"] == {"tethered_imported": True, "active": True, "locked": False}
        enforces(server, "/wiki", port=OTHER_PORT, other_port=ALLOWED_PORT)


# ── %{GLOBAL} next to other application groups ────────────────────────


class TestGlobalNextToOtherGroups:
    """mod_wsgi does not always run a ``%{GLOBAL}`` request in the main interpreter.

    This is mod_wsgi with CPython and has nothing to do with tethered: the
    first test has no tethered in it.  With one worker thread it is the
    same every time (10 of 10 starts on each version): from Python 3.12, a
    ``%{GLOBAL}`` request that is served by a thread which served another
    group before runs in that group's subinterpreter, where mod_wsgi then
    imports the script a second time; on Python 3.11 it runs in the main
    interpreter.  With several threads both happen on every version, in
    proportions that vary, so those tests assert what holds either way.
    """

    def test_without_tethered_a_global_request_runs_where_its_thread_was_last(self) -> None:
        server = start_apps(
            {"main": PLAIN_APP, "sub": PLAIN_APP},
            daemon="processes=1 threads=1",
            groups={"main": GLOBAL},
        )
        before = whoami(server, "main")
        assert before["group"] == "" and before["main_interpreter"] is True, before
        sub = whoami(server, "sub")
        assert sub["main_interpreter"] is False, sub
        after = whoami(server, "main")
        assert after["group"] == "", after
        assert after["tethered_imported"] is False, after
        if MISROUTES:
            assert after["interpreter"] == sub["interpreter"], after
            assert after["imported_in_interpreter"] == sub["interpreter"], after
        else:
            assert after["interpreter"] == before["interpreter"], after

    @pytest.mark.parametrize("threads", [1, 4])
    def test_under_a_lock_a_global_request_gets_no_network_or_the_other_groups_policy(
        self, threads: int
    ) -> None:
        # The shop, in a group of its own, holds the lock; the application in
        # %{GLOBAL} never imports tethered.  A request for it runs either in
        # the main interpreter, which is outside the lock, or in the shop's
        # interpreter, under the shop's policy.  Either way nothing forbidden
        # gets out.
        server = start_apps(
            {"main": PLAIN_APP, "shop": LOCKED},
            daemon=f"processes=1 threads={threads}",
            groups={"main": GLOBAL},
        )
        is_unrestricted(server, "/main")  # no policy in the process yet
        shop = whoami(server, "shop")
        assert standing(shop) == "holder", shop
        if threads > 1:
            # Let every worker thread serve both groups.
            together(server, ["/main/whoami", "/shop/whoami"] * threads)

        reset_arrivals()
        seen = set()
        for _ in range(2 * threads):
            report = ask(server, "/main", "connect", FORBIDDEN_NAME, OTHER_PORT)
            assert report["group"] == "", report
            if report["interpreter"] == shop["interpreter"]:
                refused(report, EGRESS_BLOCKED)
                assert "is not in the allow list" in report["message"], report
                seen.add("the shop's policy")
            else:
                assert report["main_interpreter"] is True, report
                assert report["exception"] == RUNTIME_ERROR, report
                assert LOCKED_ELSEWHERE in report["message"], report
                seen.add("no network")
        assert arrivals() == {}
        if threads == 1:
            assert seen == ({"the shop's policy"} if MISROUTES else {"no network"})
        enforces(server, "/shop")
