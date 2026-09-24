"""CycloneDX JSON BOM 导入：转换后复用内置 manifest 的兼容矩阵与冲突路径分析。

识别字段：

* ``bomFormat`` —— 必须为 ``"CycloneDX"``（否则 422 拒绝，不做静默猜测）；
* ``components[]`` 及 ``metadata.component`` —— 组件节点，``bom-ref`` 作为
  依赖引用键，并映射到规范化的 ``name@version`` 包节点（嵌套 ``components``
  递归展平；嵌套关系本身不暗示依赖边）；
* ``dependencies[]`` —— 每项 ``ref`` + ``dependsOn[]``，还原 *使用方 -> 被依赖方*
  的依赖边；引用不到任何组件的 ``ref`` / ``dependsOn`` 保留为未解析告警。

许可证取每个组件 ``licenses`` 中首个可用项：优先 SPDX ``expression`` 或 SPDX
``id``（二者按条目顺序取先出现者），其次取许可名称 ``name``（可能无法被矩阵
识别，按 unknown 处理）。完全缺失许可证同样按未知（UNLICENSED）处理。

严格校验（返回明确 422，避免静默合并）：

* 同一 ``bom-ref`` 被多个组件重复使用（违反 CycloneDX 的 bom-ref 唯一性）；
* 规范化后同名同版本的组件声明了不同的许可证。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from . import analyzer, licenses as lic

BOM_FORMAT = "CycloneDX"
EDGE_ORIGIN = "cyclonedx-dependencies"
UNRESOLVED_REASON = "bom-ref 未在 components 中声明"


class CycloneDXImportError(ValueError):
    """CycloneDX BOM 结构性错误；API 层映射为 HTTP 422。"""


# --- 许可证提取 -------------------------------------------------------------


def extract_license(component: Dict[str, Any]) -> Tuple[Optional[str], List[str]]:
    """返回 ``(许可证原文, 告警)``；许可证缺失时原文为 None（按未知处理）。

    按 licenses 条目顺序，expression 与 id 取先出现者；都没有时退回首个 name。
    """
    raw_licenses = component.get("licenses")
    if raw_licenses is None:
        return None, []
    if not isinstance(raw_licenses, list):
        return None, [
            "组件 %s 的 licenses 字段不是数组，许可证按未知处理。"
            % _component_label(component)
        ]

    named: Optional[str] = None
    warnings: List[str] = []
    for entry in raw_licenses:
        if not isinstance(entry, dict):
            continue
        # 现代写法：{"expression": "..."} 或 {"license": {"id"/"name": ...}}
        expression = entry.get("expression")
        if isinstance(expression, str) and expression.strip():
            return expression.strip(), warnings
        license_obj = entry.get("license")
        if not isinstance(license_obj, dict):
            # 兼容旧写法：条目直接平铺 {"id": ...} / {"name": ...}
            license_obj = entry
        spdx_id = license_obj.get("id")
        if isinstance(spdx_id, str) and spdx_id.strip():
            return spdx_id.strip(), warnings
        name = license_obj.get("name")
        if isinstance(name, str) and name.strip() and named is None:
            named = name.strip()
    if named is not None:
        return named, warnings
    return None, warnings


def _component_label(component: Dict[str, Any]) -> str:
    ref = component.get("bom-ref") or component.get("purl")
    if ref:
        return str(ref)
    return "%s@%s" % (component.get("name", "?"), component.get("version", "*"))


# --- BOM 装载到图构建器 ------------------------------------------------------


def populate(builder: "analyzer._GraphBuilder", document: Dict[str, Any], fallback_name: str) -> str:
    """校验 CycloneDX BOM、登记节点与依赖边到 ``builder``，返回展示名称。

    结构性问题抛 :class:`CycloneDXImportError`；引用缺失等可恢复问题写入
    builder 的未解析列表/告警。
    """
    bom_format = document.get("bomFormat")
    if bom_format != BOM_FORMAT:
        raise CycloneDXImportError(
            "bomFormat 为 %r，当前仅支持 CycloneDX JSON（bomFormat=%r）。"
            % (bom_format, BOM_FORMAT)
        )

    # bom-ref -> 规范化节点 id；同名同版本不同许可证的冲突检测也靠它。
    ref_to_nid: Dict[str, str] = {}
    nid_license: Dict[str, Tuple[str, str, Optional[str]]] = {}

    def register(component: Any) -> str:
        if not isinstance(component, dict):
            raise CycloneDXImportError("components 中存在非对象条目：%r" % (component,))

        bom_ref = component.get("bom-ref")
        bom_ref = str(bom_ref).strip() if bom_ref is not None else ""
        if bom_ref and bom_ref in ref_to_nid:
            raise CycloneDXImportError(
                "bom-ref %r 在 BOM 中重复出现（CycloneDX 要求 bom-ref 全局唯一），"
                "无法确定依赖引用指向，请修正后重新提交。" % bom_ref
            )

        name = str(component.get("name") or "").strip()
        if not name:
            if bom_ref:
                raise CycloneDXImportError(
                    "bom-ref 为 %r 的组件缺少 name 字段，无法映射为包节点。" % bom_ref
                )
            raise CycloneDXImportError(
                "存在既无 bom-ref 又无 name 的组件，无法导入：%r" % (component,)
            )

        version, _ = analyzer.clean_version(component.get("version"))
        nid = analyzer.node_id(name, version)

        license_raw, lic_warnings = extract_license(component)
        for message in lic_warnings:
            builder.warn(message)
        info = lic.license_info(license_raw)

        if nid in nid_license:
            prev_token, prev_display, prev_ref = nid_license[nid]
            if info["token"] != prev_token:
                ref_clause = ""
                if bom_ref or prev_ref:
                    ref_clause = "（bom-ref 分别为 %r 与 %r）" % (prev_ref or "", bom_ref or "")
                raise CycloneDXImportError(
                    "同名同版本组件 %s 声明了不同许可证：%s vs %s%s，拒绝静默合并；"
                    "请统一许可证或区分版本后重新提交。"
                    % (nid, prev_display, info["display"], ref_clause)
                )
        else:
            builder.register_package(
                {
                    "name": name,
                    "version": "" if version == analyzer.UNVERSIONED else version,
                    "license": license_raw,
                }
            )
            nid_license[nid] = (str(info["token"]), str(info["display"]), bom_ref or None)

        # 显式 bom-ref 优先；未声明 bom-ref 的组件以规范化 name@version 作为隐式引用键。
        ref_to_nid[bom_ref or nid] = nid

        # 嵌套组件递归展平；父子包含关系不等于依赖关系，不合成依赖边。
        nested = component.get("components")
        if nested is not None:
            if not isinstance(nested, list):
                builder.warn("组件 %s 的 components 字段不是数组，已忽略其嵌套组件。" % _component_label(component))
            else:
                for child in nested:
                    register(child)
        return nid

    metadata = document.get("metadata")
    root_component = metadata.get("component") if isinstance(metadata, dict) else None
    if root_component is not None:
        register(root_component)

    raw_components = document.get("components")
    if raw_components is not None:
        if not isinstance(raw_components, list):
            raise CycloneDXImportError("components 字段必须是数组。")
        for component in raw_components:
            register(component)
    elif root_component is None:
        builder.warn("BOM 中没有 components / metadata.component，未导入任何组件节点。")

    _load_dependencies(document, builder, ref_to_nid)

    display_name = str(document.get("name") or "").strip()
    if not display_name and isinstance(metadata, dict):
        display_name = str(metadata.get("name") or "").strip()
    if not display_name and root_component is not None:
        display_name = str(root_component.get("name") or "").strip()
    return display_name or fallback_name


def _resolve_nid(ref: str, ref_to_nid: Dict[str, str], builder: "analyzer._GraphBuilder") -> Optional[str]:
    """bom-ref -> 已登记节点 id；映射不到时尝试 name@version 文本解析，仍失败返回 None。"""
    nid = ref_to_nid.get(ref)
    if nid is not None:
        return nid
    parsed = analyzer.split_ref(ref)
    if parsed is not None:
        candidate = analyzer.node_id(*parsed)
        if candidate in builder.nodes:
            return candidate
    return None


def _load_dependencies(
    document: Dict[str, Any],
    builder: "analyzer._GraphBuilder",
    ref_to_nid: Dict[str, str],
) -> None:
    raw_dependencies = document.get("dependencies")
    if raw_dependencies is None:
        return
    if not isinstance(raw_dependencies, list):
        raise CycloneDXImportError("dependencies 字段必须是数组。")

    for entry in raw_dependencies:
        if not isinstance(entry, dict):
            raise CycloneDXImportError("dependencies 中存在非对象条目：%r" % (entry,))
        source_ref = entry.get("ref")
        if source_ref is None or not str(source_ref).strip():
            builder.warn("dependencies 中存在缺少 ref 的条目，已跳过：%r" % (entry,))
            continue
        source_ref = str(source_ref).strip()
        source = _resolve_nid(source_ref, ref_to_nid, builder)
        if source is None:
            # 起点都不存在，其整条依赖声明无法落到图上，保留为未解析告警。
            builder.mark_unresolved(source_ref, "（dependsOn 全部条目）", UNRESOLVED_REASON)
            continue
        depends_on = entry.get("dependsOn")
        if depends_on is None:
            continue
        if not isinstance(depends_on, list):
            raise CycloneDXImportError("dependencies 项 %r 的 dependsOn 必须是数组。" % source_ref)
        for target_ref in depends_on:
            if target_ref is None or not str(target_ref).strip():
                continue
            target_ref = str(target_ref).strip()
            target = _resolve_nid(target_ref, ref_to_nid, builder)
            if target is None:
                builder.mark_unresolved(source, target_ref, UNRESOLVED_REASON)
            elif source != target:
                builder.add_edge(source, target, EDGE_ORIGIN)
