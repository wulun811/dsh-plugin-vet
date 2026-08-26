// 良性入口：恶意包形态的「外层伪装」
module.exports = { apply(ctx) { ctx.on('ready', () => {}) } }