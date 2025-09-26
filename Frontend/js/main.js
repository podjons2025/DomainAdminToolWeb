// 全局变量
let currentPage = 1;
const pageSize = 20;
let isConnected = false;
let selectedGroup = null;
let selectedUsers = [];

// DOM元素引用
const usersBody = document.getElementById('users-body');
const groupsBody = document.getElementById('groups-body');
const messageBox = document.getElementById('message-box');
const messageContent = document.getElementById('message-content');
const closeMessage = document.getElementById('close-message');

// 显示消息
function showMessage(text, type = 'info', persist = false) {
    messageContent.textContent = text;
    messageBox.className = 'message-box';
    messageBox.classList.add(type);
    messageBox.classList.remove('hidden');
    
    // 仅非错误消息和非持久消息自动关闭
    if (type !== 'error' && !persist) {
        setTimeout(() => {
            messageBox.classList.add('hidden');
        }, 5000);
    }
}

// 关闭消息
closeMessage.addEventListener('click', () => {
    messageBox.classList.add('hidden');
});

// 安全的JSON解析函数
function safeJsonParse(response) {
    return new Promise((resolve, reject) => {
        response.text().then(text => {
            try {
                // 尝试解析JSON
                if (!text) {
                    return resolve({ success: false, message: '空响应' });
                }
                const json = JSON.parse(text);
                resolve(json);
            } catch (e) {
                // 解析失败时返回错误信息
                console.error('JSON解析错误:', e, '响应内容:', text);
                reject(new Error(`服务器响应格式错误: ${text.substring(0, 100)}...`));
            }
        }).catch(error => {
            reject(new Error(`读取响应失败: ${error.message}`));
        });
    });
}

// 通用API请求函数
async function apiRequest(url, method = 'GET', data = null) {
    try {
        const options = {
            method: method,
            headers: {}
        };
        
        // 添加CSRF和会话信息
        const sessionId = getCookie('SessionId');
        if (sessionId) {
            options.headers['Cookie'] = `SessionId=${sessionId}`;
        }
        
        // 添加数据
        if (data) {
            options.headers['Content-Type'] = 'application/json';
            options.body = JSON.stringify(data);
        }
        
        const response = await fetch(url, options);
        
        // 处理HTTP错误状态
        if (!response.ok) {
            const errorData = await safeJsonParse(response);
            throw new Error(errorData.message || `请求失败 (${response.status})`);
        }
        
        // 解析响应
        return await safeJsonParse(response);
    } catch (error) {
        console.error(`API请求错误 [${url}]:`, error);
        showMessage(error.message, 'error', true);
        throw error;
    }
}

// 渲染用户表格
function renderUsersTable(users) {
    usersBody.innerHTML = '';
    
    if (users.length === 0) {
        usersBody.innerHTML = '<tr><td colspan="8" class="empty-state">未找到用户</td></tr>';
        return;
    }
    
    users.forEach(user => {
        const row = document.createElement('tr');
        row.dataset.sam = user.SamAccountName;
        
        // 行点击选中逻辑
        row.addEventListener('click', function(e) {
            if (e.target.tagName === 'BUTTON') return;
            row.classList.toggle('selected');
            updateSelectedUsers();
        });
        
        row.innerHTML = `
            <td>${user.DisplayName || '-'}</td>
            <td>${user.SamAccountName}</td>
            <td>${user.EmailAddress || '-'}</td>
            <td>${user.TelePhone || '-'}</td>
            <td>${user.Description || '-'}</td>
            <td>${user.MemberOf || '-'}</td>
            <td>
                <span class="status-label ${user.Enabled ? 'status-enabled' : 'status-disabled'}">
                    ${user.Enabled ? '启用' : '禁用'}
                </span>
            </td>
            <td class="action-buttons">
                <button class="btn ${user.Enabled ? 'danger' : 'primary'}" 
                        onclick="toggleUserStatus('${user.SamAccountName}', ${!user.Enabled})">
                    ${user.Enabled ? '禁用' : '启用'}
                </button>
            </td>
        `;
        
        usersBody.appendChild(row);
    });
}

// 加载用户列表
async function loadUsers() {
    try {
        const data = await apiRequest(`/api/users?page=${currentPage}&pageSize=${pageSize}`);
        if (data.success) {
            renderUsersTable(data.users);
            renderPagination(data.total, data.page, data.pageSize);
            document.getElementById('user-count').textContent = `用户数: ${data.count || 0}`;
        }
    } catch (error) {
        console.error('加载用户失败:', error);
    }
}

// 渲染分页控件
function renderPagination(total, currentPage, pageSize) {
    const totalPages = Math.ceil(total / pageSize);
    const paginationContainer = document.getElementById('pagination-users');
    if (!paginationContainer) return;
    
    paginationContainer.innerHTML = `
        <div class="pagination">
            <button onclick="changePage(${currentPage - 1})" ${currentPage === 1 ? 'disabled' : ''}>上一页</button>
            <span>第 ${currentPage}/${totalPages} 页</span>
            <button onclick="changePage(${currentPage + 1})" ${currentPage >= totalPages ? 'disabled' : ''}>下一页</button>
        </div>
    `;
}

// 切换页码
function changePage(page) {
    if (page < 1) return;
    currentPage = page;
    loadUsers();
}

// 密码验证函数
function validatePassword(password) {
    if (password.length < 8) return "密码长度至少8位";
    if (!/[A-Z]/.test(password)) return "需包含大写字母";
    if (!/[a-z]/.test(password)) return "需包含小写字母";
    if (!/[0-9]/.test(password)) return "需包含数字";
    if (!/[^a-zA-Z0-9]/.test(password)) return "需包含特殊字符（如@#$）";
    return null;
}

// 辅助函数：获取Cookie
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
}

// 初始化页面
document.addEventListener('DOMContentLoaded', function() {
    // DOM元素引用
    const connectionForm = document.getElementById('connection-form');
    const connectBtn = document.getElementById('connect-btn');
    const disconnectBtn = document.getElementById('disconnect-btn');
    const connectionStatus = document.getElementById('connection-status');
    const userCountElem = document.getElementById('user-count');
    const groupCountElem = document.getElementById('group-count');
    const currentOuDisplay = document.getElementById('current-ou-display');
    
    // 面板引用
    const connectionPanel = document.getElementById('connection-panel');
    const ouPanel = document.getElementById('ou-panel');
    const userPanel = document.getElementById('user-panel');
    const groupPanel = document.getElementById('group-panel');
    
    // OU相关元素
    const switchOuBtn = document.getElementById('switch-ou-btn');
    const createOuBtn = document.getElementById('create-ou-btn');
    const newOuName = document.getElementById('new-ou-name');
    const ouDialog = document.getElementById('ou-dialog');
    const ouSelect = document.getElementById('ou-select');
    const confirmOu = document.getElementById('confirm-ou');
    const cancelOu = document.getElementById('cancel-ou');
    
    // 用户相关元素
    const userSearch = document.getElementById('user-search');
    const refreshUsersBtn = document.getElementById('refresh-users-btn');
    const toggleUserFormBtn = document.getElementById('toggle-user-form-btn');
    const userForm = document.getElementById('user-form');
    const cancelUserBtn = document.getElementById('cancel-user-btn');
    
    // 组相关元素
    const groupSearch = document.getElementById('group-search');
    const refreshGroupsBtn = document.getElementById('refresh-groups-btn');
    const toggleGroupFormBtn = document.getElementById('toggle-group-form-btn');
    const groupForm = document.getElementById('group-form');
    const cancelGroupBtn = document.getElementById('cancel-group-btn');
    const addUsersToGroupBtn = document.getElementById('add-users-to-group-btn');
    
    // 检查连接状态
	async function checkConnectionStatus() {
		try {
			const data = await apiRequest('/api/connection-status');
			isConnected = data.connected; // 关键：以后端返回的connected为准
			connectionStatus.textContent = data.connected ? `已连接到: ${data.domain}` : '未连接到域';
			
			// 更新UI状态时，严格依赖data.connected
			if (isConnected) {
				connectBtn.disabled = true;
				disconnectBtn.disabled = false;
				ouPanel.style.display = 'block';
				userPanel.style.display = 'block';
				groupPanel.style.display = 'block';
				// 主动加载用户/组列表（确保连接成功后触发）
				loadUsers();
				loadGroups();
			} else {
				connectBtn.disabled = false;
				disconnectBtn.disabled = true;
				ouPanel.style.display = 'none';
				userPanel.style.display = 'none';
				groupPanel.style.display = 'none';
			}
		} catch (error) {
			showMessage('检查连接状态失败: ' + error.message, 'error');
			isConnected = false; // 异常时强制标记为未连接
		}
	}

 
    // 连接到域
    connectionForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const domain = document.getElementById('domain').value;
        const username = document.getElementById('admin-user').value;
        const password = document.getElementById('admin-password').value;
        
        try {
            const data = await apiRequest('/api/connect', 'POST', {
                domain: domain,
                username: username,
                password: password
            });
            
            showMessage('连接成功', 'success');
            currentOuDisplay.textContent = data.currentOU;
            checkConnectionStatus();
        } catch (error) {
            console.error('连接失败:', error);
        }
    });
    
    // 断开连接
    disconnectBtn.addEventListener('click', async function() {
        if (confirm('确定要断开与域的连接吗？')) {
            try {
                await apiRequest('/api/disconnect', 'POST');
                showMessage('已成功断开连接', 'success');
                checkConnectionStatus();
            } catch (error) {
                console.error('断开连接失败:', error);
            }
        }
    });
    
    // 加载OU列表
    async function loadOUs() {
        try {
            const data = await apiRequest('/api/ous');
            
            // 清空选择框
            ouSelect.innerHTML = '';
            
            // 添加OU选项
            data.ous.forEach(ou => {
                const option = document.createElement('option');
                option.value = ou.DistinguishedName;
                option.textContent = ou.Name;
                option.dataset.name = ou.Name;
                ouSelect.appendChild(option);
            });
            
            // 显示对话框
            ouDialog.classList.remove('hidden');
        } catch (error) {
            console.error('加载OU列表失败:', error);
        }
    }
    
    // 切换OU按钮
    switchOuBtn.addEventListener('click', loadOUs);
    
    // 确认选择OU
    confirmOu.addEventListener('click', async function() {
        const selectedOption = ouSelect.options[ouSelect.selectedIndex];
        if (selectedOption) {
            const ouDn = selectedOption.value;
            const ouName = selectedOption.dataset.name;
            
            try {
                const data = await apiRequest('/api/switch-ou', 'POST', {
                    ouDn: ouDn,
                    ouName: ouName
                });
                
                showMessage('已切换到: ' + ouName, 'success');
                currentOuDisplay.textContent = data.currentOU;
                userCountElem.textContent = `用户数: ${data.userCount}`;
                groupCountElem.textContent = `组数: ${data.groupCount}`;
                
                // 重新加载用户和组
                loadUsers();
                loadGroups();
                
                // 关闭对话框
                ouDialog.classList.add('hidden');
            } catch (error) {
                console.error('切换OU失败:', error);
            }
        }
    });
    
    // 取消选择OU
    cancelOu.addEventListener('click', function() {
        ouDialog.classList.add('hidden');
    });
    
    // 创建OU
    createOuBtn.addEventListener('click', async function() {
        const ouName = newOuName.value.trim();
        if (!ouName) {
            showMessage('请输入OU名称', 'error');
            return;
        }
        
        try {
            await apiRequest('/api/ous', 'POST', {
                ouName: ouName
            });
            
            showMessage('OU创建成功', 'success');
            newOuName.value = '';
            loadOUs(); // 重新加载OU列表
        } catch (error) {
            console.error('创建OU失败:', error);
        }
    });
    
    // 刷新用户列表
    refreshUsersBtn.addEventListener('click', loadUsers);
    
    // 搜索用户
    userSearch.addEventListener('input', async function() {
        const filter = this.value.trim();
        
        try {
            const data = await apiRequest(`/api/users/filter?filter=${encodeURIComponent(filter)}`);
            renderUsersTable(data.users);
        } catch (error) {
            console.error('搜索用户失败:', error);
        }
    });
    
    // 切换用户表单显示
    toggleUserFormBtn.addEventListener('click', function() {
        userForm.style.display = userForm.style.display === 'none' ? 'block' : 'none';
    });
    
    // 取消创建用户
    cancelUserBtn.addEventListener('click', function() {
        userForm.reset();
        userForm.style.display = 'none';
    });
    
    // 创建用户
    userForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const cnName = document.getElementById('cn-name').value.trim();
        const username = document.getElementById('username').value.trim();
        const email = document.getElementById('email').value.trim();
        const phone = document.getElementById('phone').value.trim();
        const description = document.getElementById('description').value.trim();
        const password = document.getElementById('new-password').value;
        const confirmPassword = document.getElementById('confirm-password').value;
        const neverExpire = document.getElementById('never-expire').checked;
        
        // 客户端验证
        if (!cnName || !username || !password || !confirmPassword) {
            showMessage('请填写必填字段', 'error');
            return;
        }
        
        if (password !== confirmPassword) {
            showMessage('两次输入的密码不一致', 'error');
            return;
        }
        
        const passwordError = validatePassword(password);
        if (passwordError) {
            showMessage(passwordError, 'error');
            return;
        }
        
        try {
            const data = await apiRequest('/api/users', 'POST', {
                cnName: cnName,
                username: username,
                email: email,
                phone: phone,
                description: description,
                password: password,
                confirmPassword: confirmPassword,
                neverExpire: neverExpire
            });
            
            showMessage('用户创建成功', 'success');
            userForm.reset();
            userForm.style.display = 'none';
            loadUsers();
            userCountElem.textContent = `用户数: ${data.userCount}`;
        } catch (error) {
            console.error('创建用户失败:', error);
        }
    });
    
    // 切换用户状态（启用/禁用）
    window.toggleUserStatus = async function(username, newState) {
        const action = newState ? '启用' : '禁用';
        if (confirm(`确定要${action}用户 [${username}] 吗？`)) {
            try {
                const data = await apiRequest('/api/users/enable', 'PUT', {
                    username: username,
                    newState: newState
                });
                
                showMessage(data.message, 'success');
                loadUsers();
            } catch (error) {
                console.error(`${action}用户失败:`, error);
            }
        }
    };
    
    // 加载组列表
    async function loadGroups() {
        try {
            const data = await apiRequest('/api/groups');
            renderGroupsTable(data.groups);
            groupCountElem.textContent = `组数: ${data.count || 0}`;
        } catch (error) {
            console.error('加载组失败:', error);
        }
    }
    
    // 渲染组表格
    function renderGroupsTable(groups) {
        groupsBody.innerHTML = '';
        selectedGroup = null;
        addUsersToGroupBtn.disabled = true;
        
        if (groups.length === 0) {
            groupsBody.innerHTML = '<tr><td colspan="4" class="empty-state">没有找到组</td></tr>';
            return;
        }
        
        groups.forEach(group => {
            const row = document.createElement('tr');
            row.dataset.sam = group.SamAccountName;
            
            // 点击行选择组
            row.addEventListener('click', function() {
                // 移除其他行的选中状态
                document.querySelectorAll('#groups-table tbody tr.selected').forEach(r => {
                    r.classList.remove('selected');
                });
                
                // 添加当前行的选中状态
                row.classList.add('selected');
                selectedGroup = group.SamAccountName;
                
                // 更新按钮状态
                addUsersToGroupBtn.disabled = selectedUsers.length === 0;
            });
            
            row.innerHTML = `
                <td>${group.Name}</td>
                <td>${group.SamAccountName}</td>
                <td>${group.Description || '-'}</td>
                <td class="action-buttons">
                    <button class="btn secondary" onclick="viewGroupMembers('${group.SamAccountName}')">
                        成员
                    </button>
                </td>
            `;
            
            groupsBody.appendChild(row);
        });
    }
    
    // 刷新组列表
    refreshGroupsBtn.addEventListener('click', loadGroups);
    
    // 搜索组
    groupSearch.addEventListener('input', async function() {
        const filter = this.value.trim();
        
        try {
            const data = await apiRequest(`/api/groups/filter?filter=${encodeURIComponent(filter)}`);
            renderGroupsTable(data.groups);
        } catch (error) {
            console.error('搜索组失败:', error);
        }
    });
    
    // 切换组表单显示
    toggleGroupFormBtn.addEventListener('click', function() {
        groupForm.style.display = groupForm.style.display === 'none' ? 'block' : 'none';
    });
    
    // 取消创建组
    cancelGroupBtn.addEventListener('click', function() {
        groupForm.reset();
        groupForm.style.display = 'none';
    });
    
    // 创建组
    groupForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const groupName = document.getElementById('group-name').value.trim();
        const groupSam = document.getElementById('group-sam').value.trim();
        const groupDescription = document.getElementById('group-description').value.trim();
        
        // 客户端验证
        if (!groupName || !groupSam) {
            showMessage('组名称和组账号不能为空', 'error');
            return;
        }
        
        try {
            const data = await apiRequest('/api/groups', 'POST', {
                groupName: groupName,
                groupSam: groupSam,
                groupDescription: groupDescription
            });
            
            showMessage('组创建成功', 'success');
            groupForm.reset();
            groupForm.style.display = 'none';
            loadGroups();
            groupCountElem.textContent = `组数: ${data.groupCount}`;
        } catch (error) {
            console.error('创建组失败:', error);
        }
    });
    
    // 更新选中的用户列表
    function updateSelectedUsers() {
        selectedUsers = [];
        document.querySelectorAll('#users-table tbody tr.selected').forEach(row => {
            selectedUsers.push(row.dataset.sam);
        });
        
        // 更新添加用户到组按钮状态
        addUsersToGroupBtn.disabled = selectedUsers.length === 0 || !selectedGroup;
    }
    
    // 添加用户到组
    addUsersToGroupBtn.addEventListener('click', async function() {
        if (!selectedGroup || selectedUsers.length === 0) {
            showMessage('请先选择一个组和至少一个用户', 'error');
            return;
        }
        
        if (confirm(`确定要将 ${selectedUsers.length} 个用户添加到组 [${selectedGroup}] 吗？`)) {
            try {
                const data = await apiRequest('/api/groups/add-user', 'POST', {
                    groupSam: selectedGroup,
                    userSams: selectedUsers
                });
                
                showMessage(data.message, 'success');
                
                // 取消选择
                document.querySelectorAll('#users-table tbody tr.selected').forEach(row => {
                    row.classList.remove('selected');
                });
                document.querySelectorAll('#groups-table tbody tr.selected').forEach(row => {
                    row.classList.remove('selected');
                });
                
                selectedUsers = [];
                selectedGroup = null;
                addUsersToGroupBtn.disabled = true;
                
                // 刷新用户列表以显示更新后的组信息
                loadUsers();
            } catch (error) {
                console.error('添加用户到组失败:', error);
            }
        }
    });
    
    // 查看组成员
    window.viewGroupMembers = function(groupSam) {
        showMessage(`查看组 [${groupSam}] 的成员功能待实现`, 'info');
    };
    
    // 初始化
    checkConnectionStatus();
    
    // 定期检查连接状态
    setInterval(checkConnectionStatus, 30000); // 每30秒检查一次
});
