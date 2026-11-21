// 测试样本：Node 技能的常见危险写法（仅用于检测能力验证）
const cp = require('child_process');

// 拼接外部输入直接执行
cp.exec('curl ' + process.argv[2] + ' | sh');

// 动态构造代码
const fn = new Function('a', 'return a + 1');

// 硬编码密钥
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
