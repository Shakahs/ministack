"""A test that has MiniStack's image loaded into the container runtime before it runs.

`ministack_test` runs :image_load, rules_img's loader for the image this build made, which loads
it as ministack:<digest>, names that image to the Amazon Services Dev Services in
MINISTACK_IMAGE (quarkus.aws.devservices.ministack.image-name), and runs `test`, whose
environment it carries. Docker skips the layers it already holds.
"""

load("@bazel_skylib//lib:shell.bzl", "shell")

def _rlocation(ctx, file):
    if file.short_path.startswith("../"):
        return file.short_path[len("../"):]
    return ctx.workspace_name + "/" + file.short_path

def _ministack_test_impl(ctx):
    test = ctx.attr.test[DefaultInfo]
    loader = ctx.attr._image_load[DefaultInfo]
    digest = ctx.file._image_digest
    launcher = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.write(
        output = launcher,
        content = """#!/usr/bin/env bash
set -euo pipefail
"$TEST_SRCDIR"/{loader}
digest="$(< "$TEST_SRCDIR"/{digest})"
export MINISTACK_IMAGE="ministack:${{digest#sha256:}}"
exec "$TEST_SRCDIR"/{test} "$@"
""".format(
            loader = shell.quote(_rlocation(ctx, loader.files_to_run.executable)),
            digest = shell.quote(_rlocation(ctx, digest)),
            test = shell.quote(_rlocation(ctx, test.files_to_run.executable)),
        ),
        is_executable = True,
    )
    runfiles = ctx.runfiles(files = [
        loader.files_to_run.executable,
        digest,
        test.files_to_run.executable,
    ]).merge_all([loader.default_runfiles, test.default_runfiles])
    providers = [DefaultInfo(executable = launcher, runfiles = runfiles)]
    if RunEnvironmentInfo in ctx.attr.test:
        providers.append(ctx.attr.test[RunEnvironmentInfo])
    return providers

ministack_test = rule(
    implementation = _ministack_test_impl,
    test = True,
    attrs = {
        "test": attr.label(
            doc = "The test to run once the image is loaded. Tag it `manual`: this target runs it.",
            executable = True,
            cfg = "target",
            mandatory = True,
        ),
        "_image_digest": attr.label(
            default = Label("//vendor/ministack:image_digest"),
            allow_single_file = True,
        ),
        "_image_load": attr.label(
            default = Label("//vendor/ministack:image_load"),
            executable = True,
            cfg = "target",
        ),
    },
)
