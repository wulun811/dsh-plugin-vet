// 良性入口：供应链攻击的真实载体是安装期钩子而非插件代码
module.exports = { apply(ctx) { ctx.on('ready', () => {}) } }