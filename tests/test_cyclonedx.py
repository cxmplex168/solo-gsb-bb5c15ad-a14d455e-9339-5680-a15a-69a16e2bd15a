"""CycloneDX JSON BOM 导入的轻量自测：python -m tests.test_cyclonedx"""

from __future__ import annotations

from app import analyzer, cyclonedx


def _check(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError("%s %s" % (name, detail))
    print("ok -", name)


def _expect_422(name: str, bom: dict) -> None:
    try:
        analyzer.analyze_manifest(bom)
    except cyclonedx.CycloneDXImportError:
        print("ok -", name)
        return
    raise AssertionError("%s: 应当返回 422（CycloneDXImportError）" % name)


def _component(bom_ref: str, name: str, version: str = "1.0.0", license_id=None,
               expression=None, license_name=None, nested=None, no_license=False):
    licenses = None
    if not no_license:
        if expression is not None:
            licenses = [{"expression": expression}]
        elif license_id is not None:
            licenses = [{"license": {"id": license_id}}]
        elif license_name is not None:
            licenses = [{"license": {"name": license_name}}]
        else:
            licenses = [{"license": {"id": "MIT"}}]
    comp = {"bom-ref": bom_ref, "name": name, "version": version}
    if licenses is not None:
        comp["licenses"] = licenses
    if nested is not None:
        comp["components"] = nested
    return comp


def test_basic_import_and_format() -> None:
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "name": "demo-bom",
        "components": [
            _component("ref-app", "app", "1.0", "GPL-3.0"),
            _component("ref-lib", "lib", "2.0", "Proprietary"),
        ],
        "dependencies": [{"ref": "ref-app", "dependsOn": ["ref-lib"]}],
    }
    result = analyzer.analyze_manifest(bom)
    _check("input format flagged", result["input_format"] == analyzer.CYCLONEDX_FORMAT)
    _check("name taken from bom", result["manifest_name"] == "demo-bom")
    _check("two nodes", result["summary"]["packages"] == 2)
    _check("one edge", result["summary"]["edges"] == 1, str(result["edges"]))
    _check("edge from cyclonedx", result["edges"][0]["from"] == cyclonedx.EDGE_ORIGIN)
    _check("bom-ref mapped to name@version nodes",
           {n["id"] for n in result["nodes"]} == {"app@1.0", "lib@2.0"})


def test_conflict_path_reuses_matrix() -> None:
    bom = {
        "bomFormat": "CycloneDX",
        "components": [
            _component("app", "app", "1", "GPL-2.0"),
            _component("apache-lib", "apache-lib", "1", "Apache-2.0"),
        ],
        "dependencies": [{"ref": "app", "dependsOn": ["apache-lib"]}],
    }
    result = analyzer.analyze_manifest(bom)
    _check("gpl2 vs apache hard conflict", result["status"] == "conflict")
    c = result["conflicts"][0]
    _check("conflict severity error", c["severity"] == "error")
    _check("shortest path reconstructed", c["path"] == ["app@1", "apache-lib@1"], str(c["path"]))


def test_spdx_id_expression_name_priority() -> None:
    bom = {
        "bomFormat": "CycloneDX",
        "components": [
            _component("a", "id-pkg", "1", license_id="Apache-2.0"),
            _component("b", "expr-pkg", "1", expression="MIT"),
            _component("c", "name-pkg", "1", license_name="GPLv3"),
            _component("d", "missing-pkg", "1", no_license=True),
        ],
    }
    result = analyzer.analyze_manifest(bom)
    by_name = {n["name"]: n for n in result["nodes"]}
    _check("spdx id normalized", by_name["id-pkg"]["license"] == "Apache-2.0")
    _check("expression used", by_name["expr-pkg"]["license"] == "MIT")
    _check("name alias normalized", by_name["name-pkg"]["license"] == "GPL-3.0",
           by_name["name-pkg"]["license"])
    _check("missing license unknown",
           by_name["missing-pkg"]["license_known"] is False
           and by_name["missing-pkg"]["license_category"] == "unknown",
           str(by_name["missing-pkg"]))


def test_unresolved_refs() -> None:
    bom = {
        "bomFormat": "CycloneDX",
        "components": [_component("app", "app", "1", "MIT")],
        "dependencies": [
            {"ref": "app", "dependsOn": ["ghost-ref"]},
            {"ref": "ghost-source", "dependsOn": ["app"]},
        ],
    }
    result = analyzer.analyze_manifest(bom)
    refs = {(u["source"], u["reference"]): u["reason"] for u in result["unresolved"]}
    _check("missing target unresolved", refs[("app@1", "ghost-ref")] == cyclonedx.UNRESOLVED_REASON)
    _check("missing source unresolved", ("ghost-source", "（dependsOn 全部条目）") in refs)
    _check("no phantom edges", result["summary"]["edges"] == 0)
    _check("warnings rendered", any("ghost-ref" in w for w in result["warnings"]))


def test_duplicate_bom_ref_422() -> None:
    bom = {"bomFormat": "CycloneDX", "components": [
        _component("dup", "a", "1", "MIT"),
        _component("dup", "a", "1", "MIT"),
    ]}
    _expect_422("duplicate bom-ref rejected even for same component", bom)


def test_same_name_version_different_license_422() -> None:
    bom = {"bomFormat": "CycloneDX", "components": [
        _component("r1", "lib", "1.0", "MIT"),
        _component("r2", "lib", "1.0", "GPL-3.0"),
    ]}
    _expect_422("same name@version different license rejected", bom)


def test_same_name_version_same_license_merged() -> None:
    bom = {"bomFormat": "CycloneDX", "components": [
        _component("r1", "lib", "1.0", "MIT"),
        _component("r2", "lib", "1.0", expression="MIT"),
    ]}
    result = analyzer.analyze_manifest(bom)
    _check("identical component merged to one node", result["summary"]["packages"] == 1)


def test_unsupported_bom_format_422() -> None:
    _expect_422("non-CycloneDX bomFormat rejected", {"bomFormat": "SPDX", "components": []})


def test_metadata_component_and_nested() -> None:
    bom = {
        "bomFormat": "CycloneDX",
        "metadata": {"component": _component("root", "web-app", "1.0", "AGPL-3.0")},
        "components": [
            _component("outer", "outer", "1", "MIT", nested=[
                _component("inner", "inner", "1", "Proprietary"),
            ]),
        ],
        "dependencies": [{"ref": "root", "dependsOn": ["outer", "inner"]}],
    }
    result = analyzer.analyze_manifest(bom)
    ids = {n["id"] for n in result["nodes"]}
    _check("metadata component registered", "web-app@1.0" in ids, str(ids))
    _check("nested component flattened", "inner@1" in ids, str(ids))
    _check("edges resolve via bom-refs", result["summary"]["edges"] == 2, str(result["edges"]))
    _check("nested inclusion adds no synthetic edge",
           {tuple(sorted((e["source"], e["target"]))) for e in result["edges"]}
           == {("outer@1", "web-app@1.0"), ("inner@1", "web-app@1.0")}
           or {tuple((e["source"], e["target"])) for e in result["edges"]}
           == {("web-app@1.0", "outer@1"), ("web-app@1.0", "inner@1")},
           str(result["edges"]))


def test_self_dependency_skipped_and_dedup() -> None:
    bom = {
        "bomFormat": "CycloneDX",
        "components": [
            _component("app", "app", "1", "MIT"),
            _component("lib", "lib", "1", "MIT"),
        ],
        "dependencies": [
            {"ref": "app", "dependsOn": ["lib", "lib"]},
            {"ref": "app", "dependsOn": ["app", "lib"]},
        ],
    }
    result = analyzer.analyze_manifest(bom)
    _check("single edge after dedup, self-edge skipped", result["summary"]["edges"] == 1)


def test_missing_bom_ref_uses_implicit_name_version() -> None:
    bom = {
        "bomFormat": "CycloneDX",
        "components": [
            {"name": "app", "version": "1", "licenses": [{"license": {"id": "MIT"}}]},
            {"name": "lib", "version": "2", "licenses": [{"license": {"id": "ISC"}}]},
        ],
        "dependencies": [{"ref": "app@1", "dependsOn": ["lib@2"]}],
    }
    result = analyzer.analyze_manifest(bom)
    _check("implicit refs resolve", result["summary"]["edges"] == 1, str(result["unresolved"]))


def test_native_manifest_still_recognized() -> None:
    manifest = {"name": "native", "packages": [{"name": "a", "version": "1", "license": "MIT"}]}
    result = analyzer.analyze_manifest(manifest)
    _check("native format flagged", result["input_format"] == analyzer.MANIFEST_FORMAT)
    _check("native package parsed", result["summary"]["packages"] == 1)


def main() -> None:
    test_basic_import_and_format()
    test_conflict_path_reuses_matrix()
    test_spdx_id_expression_name_priority()
    test_unresolved_refs()
    test_duplicate_bom_ref_422()
    test_same_name_version_different_license_422()
    test_same_name_version_same_license_merged()
    test_unsupported_bom_format_422()
    test_metadata_component_and_nested()
    test_self_dependency_skipped_and_dedup()
    test_missing_bom_ref_uses_implicit_name_version()
    test_native_manifest_still_recognized()
    print("\nall cyclonedx tests passed.")


if __name__ == "__main__":
    main()
