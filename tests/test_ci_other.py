# -*- coding: utf-8 -*-
"""§3cc 守卫：别的 CI 也会把东西送出去（GitLab / Azure / Jenkins / Compress-Archive）。"""
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import skillgate as sg  # noqa: E402

MD = "---\nname: c\ndescription: c\n---\n\n# c\n"
SEV = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

GITLAB = "stages:\n  - build\nbuild:\n  script:\n    - make\n"
AZURE = "trigger:\n  - main\npool:\n  vmImage: ubuntu-latest\nsteps:\n  - script: make\n"
JENKINS = "pipeline {\n  agent any\n  stages { stage('b') { steps { sh 'make' } } }\n}\n"


def _mk(tmp_path, files):
    d = str(tmp_path / "s")
    os.makedirs(d)
    with open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8") as f:
        f.write(MD)
    with open(os.path.join(d, "models.txt"), "w", encoding="utf-8") as f:
        f.write("ok\n")
    for rel, text in files.items():
        p = os.path.join(d, *rel.split("/"))
        if os.path.dirname(p) and not os.path.isdir(os.path.dirname(p)):
            os.makedirs(os.path.dirname(p))
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    return d


def _sev(res):
    got = [f.severity for f in res.findings if f.scoring]
    return min(got, key=lambda s: list(SEV).index(s)) if got else "NONE"


def test_gitlab_paths_dot_is_high(tmp_path):
    d = _mk(tmp_path, {".gitlab-ci.yml": GITLAB + "  artifacts:\n    paths:\n      - .\n"})
    assert _sev(sg.scan_skill(d)) == "HIGH"


def test_gitlab_paths_double_star_is_high(tmp_path):
    d = _mk(tmp_path, {".gitlab-ci.yml": GITLAB + '  artifacts:\n    paths:\n      - "**/*"\n'})
    assert _sev(sg.scan_skill(d)) == "HIGH"


def test_gitlab_untracked_is_high(tmp_path):
    d = _mk(tmp_path, {".gitlab-ci.yml": GITLAB + "  artifacts:\n    untracked: true\n"
                                          "    paths:\n      - dist/\n"})
    assert _sev(sg.scan_skill(d)) == "HIGH"


def test_gitlab_dist_with_expiry_is_clean(tmp_path):
    d = _mk(tmp_path, {".gitlab-ci.yml": GITLAB + "  artifacts:\n    paths:\n      - dist/\n"
                                          "    expire_in: 1 week\n"})
    assert _sev(sg.scan_skill(d)) in ("NONE", "LOW", "INFO")


def test_azure_sources_dir_is_high(tmp_path):
    d = _mk(tmp_path, {"azure-pipelines.yml": AZURE +
                       "  - task: PublishPipelineArtifact@1\n    inputs:\n"
                       "      targetPath: $(Build.SourcesDirectory)\n"})
    assert _sev(sg.scan_skill(d)) == "HIGH"


def test_azure_default_working_dir_is_high(tmp_path):
    d = _mk(tmp_path, {"azure-pipelines.yml":
                       AZURE + "  - task: PublishBuildArtifact@1\n    inputs:\n"
                               "      PathtoPublish: $(System.DefaultWorkingDirectory)\n"})
    assert _sev(sg.scan_skill(d)) == "HIGH"


def test_azure_staging_dir_is_clean(tmp_path):
    d = _mk(tmp_path, {"azure-pipelines.yml":
                       AZURE + "  - task: PublishPipelineArtifact@1\n    inputs:\n"
                               "      targetPath: $(Build.ArtifactStagingDirectory)\n"})
    assert _sev(sg.scan_skill(d)) in ("NONE", "LOW", "INFO")


def test_jenkins_archive_everything_is_high(tmp_path):
    d = _mk(tmp_path, {"Jenkinsfile": JENKINS.replace(
        "sh 'make'", "sh 'make'\n        archiveArtifacts artifacts: '**'")})
    assert _sev(sg.scan_skill(d)) == "HIGH"


def test_jenkins_archive_specific_is_clean(tmp_path):
    d = _mk(tmp_path, {"Jenkinsfile": JENKINS.replace(
        "sh 'make'", "sh 'make'\n        archiveArtifacts artifacts: 'dist/**/*.whl'")})
    assert _sev(sg.scan_skill(d)) in ("NONE", "LOW", "INFO")


def test_compress_archive_root_is_high(tmp_path):
    d = _mk(tmp_path, {"ci/build.ps1": "Compress-Archive -Path . -DestinationPath out.zip\n"})
    assert _sev(sg.scan_skill(d)) == "HIGH"


def test_compress_archive_dist_is_clean(tmp_path):
    d = _mk(tmp_path, {"ci/build.ps1":
                       "Compress-Archive -Path dist -DestinationPath dist/pkg.zip\n"})
    assert _sev(sg.scan_skill(d)) in ("NONE", "LOW", "INFO")


def test_jenkinsfile_inside_tests_is_excluded(tmp_path):
    d = _mk(tmp_path, {"tests/fixtures/Jenkinsfile": JENKINS.replace(
        "sh 'make'", "sh 'make'\n        archiveArtifacts '**'")})
    assert _sev(sg.scan_skill(d)) in ("NONE", "LOW", "INFO")


def test_gitlab_detector_units():
    import tempfile
    p = os.path.join(tempfile.mkdtemp(), ".gitlab-ci.yml")
    with open(p, "w", encoding="utf-8") as f:
        f.write(GITLAB + "  artifacts:\n    paths:\n      - .\n")
    assert sg._gitlab_artifacts_root(open(p, encoding="utf-8").read())
    with open(p, "w", encoding="utf-8") as f:
        f.write(GITLAB + "  artifacts:\n    paths:\n      - dist/\n")
    assert not sg._gitlab_artifacts_root(open(p, encoding="utf-8").read())


def test_jenkins_detector_units():
    assert sg._jenkins_archives_everything("archiveArtifacts artifacts: '**'")
    assert not sg._jenkins_archives_everything("archiveArtifacts artifacts: 'build/*.zip'")
