#!/usr/bin/env python3
"""
LGD-Gate: Independent Skill Evaluation
========================================
独立第三方技能评测服务。
五维评测体系：结构完整性 + 文档质量 + 安全检查 + 可运行性 + 生态兼容性
"""

import os
import sys
import re
import ast
import time

def evaluate_skill(skill_path):
    """评测一个技能。"""
    start_time = time.time()
    
    print("=" * 70)
    print("  🏛️  LGD-Gate 独立第三方评测报告")
    print("=" * 70)
    print(f"  评测对象: {skill_path}")
    print()
    
    score = 100
    findings = []
    warnings = []
    
    # ============================================================
    # 第一维：结构完整性（25分）
    # ============================================================
    print("📦 第一维：结构完整性（25分）")
    print("-" * 50)
    
    # SKILL.md
    skill_md = os.path.join(skill_path, "SKILL.md")
    if os.path.exists(skill_md):
        print("  ✅ SKILL.md 存在")
        with open(skill_md, 'r', encoding='utf-8') as f:
            content = f.read()
            
            required_fields = ['name', 'description', 'version', 'license', 'author']
            for field in required_fields:
                if f'{field}:' in content:
                    print(f"  ✅ {field} 字段完整")
                else:
                    print(f"  ⚠️ {field} 字段缺失")
                    score -= 2
                    findings.append(f"缺少 {field} 字段")
    else:
        print("  ❌ SKILL.md 不存在")
        score -= 20
        findings.append("缺少 SKILL.md")
    
    # LICENSE
    if os.path.exists(os.path.join(skill_path, "LICENSE")):
        print("  ✅ LICENSE 存在")
    else:
        print("  ⚠️ LICENSE 缺失")
        score -= 3
        findings.append("缺少 LICENSE")
    
    # README.md
    if os.path.exists(os.path.join(skill_path, "README.md")):
        print("  ✅ README.md 存在")
    else:
        print("  ⚠️ README.md 缺失")
        score -= 2
        findings.append("缺少 README.md")
    
    print()
    
    # ============================================================
    # 第二维：目录结构（15分）
    # ============================================================
    print("📁 第二维：目录结构（15分）")
    print("-" * 50)
    
    # scripts 目录
    scripts_dir = os.path.join(skill_path, "scripts")
    if os.path.exists(scripts_dir):
        print("  ✅ scripts 目录存在")
        script_files = [f for f in os.listdir(scripts_dir) if f.endswith('.py')]
        print(f"     📄 包含 {len(script_files)} 个 Python 脚本")
    else:
        print("  ⚠️ scripts 目录缺失")
        score -= 5
        findings.append("缺少 scripts 目录")
    
    # examples 目录
    examples_dir = os.path.join(skill_path, "examples")
    if os.path.exists(examples_dir):
        print("  ✅ examples 目录存在")
        example_files = os.listdir(examples_dir)
        print(f"     📄 包含 {len(example_files)} 个示例文件")
    else:
        print("  ⚠️ examples 目录缺失")
        score -= 3
        findings.append("缺少 examples 目录")
    
    # references 目录
    if os.path.exists(os.path.join(skill_path, "references")):
        print("  ✅ references 目录存在")
    else:
        print("  ℹ️ references 目录（可选）")
    
    print()
    
    # ============================================================
    # 第三维：文档质量（20分）
    # ============================================================
    print("📝 第三维：文档质量（20分）")
    print("-" * 50)
    
    if os.path.exists(skill_md):
        with open(skill_md, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # 使用场景
            if '## When to Use' in content or '## 使用场景' in content or '## 何时用' in content:
                print("  ✅ 有使用场景说明")
            else:
                print("  ⚠️ 缺少使用场景说明")
                score -= 4
                findings.append("缺少使用场景说明")
            
            # 使用方法
            if '## Usage' in content or '## 使用方法' in content or '## 怎么用' in content:
                print("  ✅ 有使用方法说明")
            else:
                print("  ⚠️ 缺少使用方法说明")
                score -= 4
                findings.append("缺少使用方法说明")
            
            # 示例
            if '## Examples' in content or '## 示例' in content or '## 例子' in content:
                print("  ✅ 有示例")
            else:
                print("  ⚠️ 缺少示例")
                score -= 3
                findings.append("缺少示例")
            
            # 已知限制
            if '## Known Limits' in content or '## 已知限制' in content:
                print("  ✅ 有已知限制说明")
            else:
                print("  ℹ️ 缺少已知限制说明（可选）")
                warnings.append("建议加上已知限制说明")
    
    print()
    
    # ============================================================
    # 第四维：安全检查（25分）
    # ============================================================
    print("🔒 第四维：安全检查（25分）")
    print("-" * 50)
    
    # 扫描所有 Python 文件
    security_issues = []
    
    if os.path.exists(scripts_dir):
        for script_file in os.listdir(scripts_dir):
            if script_file.endswith('.py'):
                script_path = os.path.join(scripts_dir, script_file)
                with open(script_path, 'r', encoding='utf-8') as f:
                    code = f.read()
                    
                    # 检查硬编码密钥
                    if re.search(r'api_key\s*=\s*["\']', code, re.IGNORECASE):
                        security_issues.append(f"{script_file}: 硬编码 API key")
                        score -= 5
                    
                    # 检查 eval/exec
                    if 'eval(' in code or 'exec(' in code:
                        security_issues.append(f"{script_file}: 使用 eval/exec")
                        score -= 3
                    
                    # 检查 os.system
                    if 'os.system(' in code:
                        security_issues.append(f"{script_file}: 使用 os.system")
                        score -= 2
    
    if security_issues:
        for issue in security_issues:
            print(f"  ❌ {issue}")
            findings.append(issue)
    else:
        print("  ✅ 未发现安全问题")
    
    print()
    
    # ============================================================
    # 第五维：生态兼容性（15分）
    # ============================================================
    print("🌐 第五维：生态兼容性（15分）")
    print("-" * 50)
    
    # 检查是否符合 SKILL.md 标准
    if os.path.exists(skill_md):
        with open(skill_md, 'r', encoding='utf-8') as f:
            content = f.read()
            if content.startswith('---'):
                print("  ✅ 符合 SKILL.md frontmatter 标准")
            else:
                print("  ⚠️ 缺少 frontmatter")
                score -= 3
                findings.append("缺少 frontmatter")
    
    # 检查是否有 tags
    if os.path.exists(skill_md):
        with open(skill_md, 'r', encoding='utf-8') as f:
            content = f.read()
            if 'tags:' in content:
                print("  ✅ 有 tags 标签")
            else:
                print("  ⚠️ 缺少 tags 标签")
                score -= 2
                warnings.append("建议加上 tags 标签")
    
    print()
    
    # ============================================================
    # 最终评分
    # ============================================================
    elapsed = time.time() - start_time
    
    print("=" * 70)
    print(f"  Trust Score: {score}/100")
    
    if score >= 90:
        grade = "A+"
        emoji = "🏆"
    elif score >= 80:
        grade = "A"
        emoji = "🥇"
    elif score >= 70:
        grade = "B"
        emoji = "🥈"
    elif score >= 60:
        grade = "C"
        emoji = "🥉"
    else:
        grade = "D"
        emoji = "⚠️"
    
    print(f"  等级: {emoji} {grade}")
    print(f"  评测耗时: {elapsed:.2f}s")
    print("=" * 70)
    
    # 改进建议
    if findings:
        print()
        print("🔧 改进建议：")
        for i, f in enumerate(findings, 1):
            print(f"  {i}. {f}")
    
    if warnings:
        print()
        print("💡 优化建议：")
        for i, w in enumerate(warnings, 1):
            print(f"  {i}. {w}")
    
    print()
    print("=" * 70)
    print("  评测完成！")
    print("=" * 70)
    
    return score, grade

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python evaluate.py <skill_path>")
        print()
        print("示例:")
        print("  python evaluate.py ./my-skill/")
        sys.exit(1)
    
    evaluate_skill(sys.argv[1])
