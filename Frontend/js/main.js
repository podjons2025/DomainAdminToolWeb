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
    
    // 消息框引用
    const messageBox = document.getElementById('message-box');
    const messageContent = document.getElementById('message-content');
    const closeMessage = document.getElementById('close-message');
    
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
    const usersBody = document.getElementById('users-body');
    
    // 组相关元素
    const groupSearch = document.getElementById('group-search');
    const refreshGroupsBtn = document.getElementById('refresh-groups-btn');
    const toggleGroupFormBtn = document.getElementById('toggle-group-form-btn');
    const groupForm = document.getElementById('group-form');
    const cancelGroupBtn = document.getElementById('cancel-group-btn');
    const groupsBody = document.getElementById('groups-body');
    const addUsersToGroupBtn = document.getElementById('add-users-to-group-btn');
    
    // 全局状态
    let isConnected = false;
    let selectedGroup = null;
    let selectedUsers = [];
    
    // 显示消息
    function showMessage(text, type = 'info') {
        messageContent.textContent = text;
        messageBox.className = 'message-box';
        messageBox.classList.add(type);
        
        // 5秒后自动关闭
        setTimeout(() => {
            messageBox.classList.add('hidden');
        }, 5000);
    }
    
    // 关闭消息
    closeMessage.addEventListener('click', () => {
        messageBox.classList.add('hidden');
    });
    
    // 检查连接状态
    function checkConnectionStatus() {
        fetch('/api/connection-status')
            .then(response => response.json())
            .then(data => {
                isConnected = data.isConnected;
                connectionStatus.textContent = data.status;
                userCountElem.textContent = `用户数: ${data.userCount}`;
                groupCountElem.textContent = `组数: ${data.groupCount}`;
                
                if (data.currentOU) {
                    currentOuDisplay.textContent = data.currentOU;
                }
                
                // 更新UI状态
                if (isConnected) {
                    connectBtn.disabled = true;
                    disconnectBtn.disabled = false;
                    ouPanel.style.display = 'block';
                    userPanel.style.display = 'block';
                    groupPanel.style.display = 'block';
                    
                    // 加载数据
                    loadUsers();
                    loadGroups();
                } else {
                    connectBtn.disabled = false;
                    disconnectBtn.disabled = true;
                    ouPanel.style.display = 'none';
                    userPanel.style.display = 'none';
                    groupPanel.style.display = 'none';
                    
                    // 清空表格
                    usersBody.innerHTML = '<tr><td colspan="8" class="empty-state">请先连接到域并加载用户</td></tr>';
                    groupsBody.innerHTML = '<tr><td colspan="4" class="empty-state">请先连接到域并加载组</td></tr>';
                }
            })
            .catch(error => {
                console.error('检查连接状态失败:', error);
                showMessage('检查连接状态失败', 'error');
            });
    }
    
    // 连接到域
    connectionForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const domain = document.getElementById('domain').value;
        const adminUser = document.getElementById('admin-user').value;
        const adminPassword = document.getElementById('admin-password').value;
        
        fetch('/api/connect', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                domain: domain,
                adminUser: adminUser,
                adminPassword: adminPassword
            })
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.message || '连接失败');
                });
            }
            return response.json();
        })
        .then(data => {
            showMessage('连接成功', 'success');
            currentOuDisplay.textContent = data.currentOU;
            checkConnectionStatus();
        })
        .catch(error => {
            console.error('连接失败:', error);
            showMessage(error.message, 'error');
        });
    });
    
    // 断开连接
    disconnectBtn.addEventListener('click', function() {
        if (confirm('确定要断开与域的连接吗？')) {
            fetch('/api/disconnect', {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                showMessage('已成功断开连接', 'success');
                checkConnectionStatus();
            })
            .catch(error => {
                console.error('断开连接失败:', error);
                showMessage('断开连接失败', 'error');
            });
        }
    });
    
    // 加载OU列表
    function loadOUs() {
        fetch('/api/ous')
            .then(response => {
                if (!response.ok) {
                    return response.json().then(data => {
                        throw new Error(data.message || '获取OU列表失败');
                    });
                }
                return response.json();
            })
            .then(data => {
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
            })
            .catch(error => {
                console.error('加载OU列表失败:', error);
                showMessage(error.message, 'error');
            });
    }
    
    // 切换OU按钮
    switchOuBtn.addEventListener('click', loadOUs);
    
    // 确认选择OU
    confirmOu.addEventListener('click', function() {
        const selectedOption = ouSelect.options[ouSelect.selectedIndex];
        if (selectedOption) {
            const ouDn = selectedOption.value;
            const ouName = selectedOption.dataset.name;
            
            fetch('/api/switch-ou', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    ouDn: ouDn,
                    ouName: ouName
                })
            })
            .then(response => {
                if (!response.ok) {
                    return response.json().then(data => {
                        throw new Error(data.message || '切换OU失败');
                    });
                }
                return response.json();
            })
            .then(data => {
                showMessage('已切换到: ' + ouName, 'success');
                currentOuDisplay.textContent = data.currentOU;
                userCountElem.textContent = `用户数: ${data.userCount}`;
                groupCountElem.textContent = `组数: ${data.groupCount}`;
                
                // 重新加载用户和组
                loadUsers();
                loadGroups();
                
                // 关闭对话框
                ouDialog.classList.add('hidden');
            })
            .catch(error => {
                console.error('切换OU失败:', error);
                showMessage(error.message, 'error');
            });
        }
    });
    
    // 取消选择OU
    cancelOu.addEventListener('click', function() {
        ouDialog.classList.add('hidden');
    });
    
    // 创建OU
    createOuBtn.addEventListener('click', function() {
        const ouName = newOuName.value.trim();
        if (!ouName) {
            showMessage('请输入OU名称', 'error');
            return;
        }
        
        fetch('/api/ous', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                ouName: ouName
            })
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.message || '创建OU失败');
                });
            }
            return response.json();
        })
        .then(data => {
            showMessage('OU创建成功', 'success');
            newOuName.value = '';
            loadOUs(); // 重新加载OU列表
        })
        .catch(error => {
            console.error('创建OU失败:', error);
            showMessage(error.message, 'error');
        });
    });
    
    // 加载用户列表
    function loadUsers() {
        fetch('/api/users')
            .then(response => {
                if (!response.ok) {
                    return response.json().then(data => {
                        throw new Error(data.message || '获取用户列表失败');
                    });
                }
                return response.json();
            })
            .then(data => {
                renderUsersTable(data.users);
                userCountElem.textContent = `用户数: ${data.count}`;
            })
            .catch(error => {
                console.error('加载用户失败:', error);
                showMessage(error.message, 'error');
            });
    }
    
    // 渲染用户表格
    function renderUsersTable(users) {
        usersBody.innerHTML = '';
        
        if (users.length === 0) {
            usersBody.innerHTML = '<tr><td colspan="8" class="empty-state">没有找到用户</td></tr>';
            return;
        }
        
        users.forEach(user => {
            const row = document.createElement('tr');
            row.dataset.sam = user.SamAccountName;
            
            // 点击行切换选择状态
            row.addEventListener('click', function(e) {
                // 如果点击的是按钮，不触发选择
                if (e.target.tagName === 'BUTTON') return;
                
                row.classList.toggle('selected');
                
                // 更新选中用户列表
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
    
    // 刷新用户列表
    refreshUsersBtn.addEventListener('click', loadUsers);
    
    // 搜索用户
    userSearch.addEventListener('input', function() {
        const filter = this.value.trim();
        
        fetch(`/api/users/filter?filter=${encodeURIComponent(filter)}`)
            .then(response => {
                if (!response.ok) {
                    return response.json().then(data => {
                        throw new Error(data.message || '搜索用户失败');
                    });
                }
                return response.json();
            })
            .then(data => {
                renderUsersTable(data.users);
            })
            .catch(error => {
                console.error('搜索用户失败:', error);
                showMessage(error.message, 'error');
            });
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
    userForm.addEventListener('submit', function(e) {
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
        
        if (password.length < 8 || 
            !/[A-Z]/.test(password) || 
            !/[a-z]/.test(password) || 
            !/[0-9]/.test(password) || 
            !/[^a-zA-Z0-9]/.test(password)) {
            showMessage('密码必须至少8位，包含大小写字母、数字和特殊字符', 'error');
            return;
        }
        
        fetch('/api/users', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                cnName: cnName,
                username: username,
                email: email,
                phone: phone,
                description: description,
                password: password,
                confirmPassword: confirmPassword,
                neverExpire: neverExpire
            })
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.message || '创建用户失败');
                });
            }
            return response.json();
        })
        .then(data => {
            showMessage('用户创建成功', 'success');
            userForm.reset();
            userForm.style.display = 'none';
            loadUsers();
            userCountElem.textContent = `用户数: ${data.userCount}`;
        })
        .catch(error => {
            console.error('创建用户失败:', error);
            showMessage(error.message, 'error');
        });
    });
    
    // 切换用户状态（启用/禁用）
    window.toggleUserStatus = function(username, newState) {
        const action = newState ? '启用' : '禁用';
        if (confirm(`确定要${action}用户 [${username}] 吗？`)) {
            fetch('/api/users/enable', {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: username,
                    newState: newState
                })
            })
            .then(response => {
                if (!response.ok) {
                    return response.json().then(data => {
                        throw new Error(data.message || `${action}用户失败`);
                    });
                }
                return response.json();
            })
            .then(data => {
                showMessage(data.message, 'success');
                loadUsers();
            })
            .catch(error => {
                console.error(`${action}用户失败:`, error);
                showMessage(error.message, 'error');
            });
        }
    };
    
    // 加载组列表
    function loadGroups() {
        fetch('/api/groups')
            .then(response => {
                if (!response.ok) {
                    return response.json().then(data => {
                        throw new Error(data.message || '获取组列表失败');
                    });
                }
                return response.json();
            })
            .then(data => {
                renderGroupsTable(data.groups);
                groupCountElem.textContent = `组数: ${data.count}`;
            })
            .catch(error => {
                console.error('加载组失败:', error);
                showMessage(error.message, 'error');
            });
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
    groupSearch.addEventListener('input', function() {
        const filter = this.value.trim();
        
        fetch(`/api/groups/filter?filter=${encodeURIComponent(filter)}`)
            .then(response => {
                if (!response.ok) {
                    return response.json().then(data => {
                        throw new Error(data.message || '搜索组失败');
                    });
                }
                return response.json();
            })
            .then(data => {
                renderGroupsTable(data.groups);
            })
            .catch(error => {
                console.error('搜索组失败:', error);
                showMessage(error.message, 'error');
            });
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
    groupForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const groupName = document.getElementById('group-name').value.trim();
        const groupSam = document.getElementById('group-sam').value.trim();
        const groupDescription = document.getElementById('group-description').value.trim();
        
        // 客户端验证
        if (!groupName || !groupSam) {
            showMessage('组名称和组账号不能为空', 'error');
            return;
        }
        
        fetch('/api/groups', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                groupName: groupName,
                groupSam: groupSam,
                groupDescription: groupDescription
            })
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.message || '创建组失败');
                });
            }
            return response.json();
        })
        .then(data => {
            showMessage('组创建成功', 'success');
            groupForm.reset();
            groupForm.style.display = 'none';
            loadGroups();
            groupCountElem.textContent = `组数: ${data.groupCount}`;
        })
        .catch(error => {
            console.error('创建组失败:', error);
            showMessage(error.message, 'error');
        });
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
    addUsersToGroupBtn.addEventListener('click', function() {
        if (!selectedGroup || selectedUsers.length === 0) {
            showMessage('请先选择一个组和至少一个用户', 'error');
            return;
        }
        
        if (confirm(`确定要将 ${selectedUsers.length} 个用户添加到组 [${selectedGroup}] 吗？`)) {
            fetch('/api/groups/add-user', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    groupSam: selectedGroup,
                    userSams: selectedUsers
                })
            })
            .then(response => {
                if (!response.ok) {
                    return response.json().then(data => {
                        throw new Error(data.message || '添加用户到组失败');
                    });
                }
                return response.json();
            })
            .then(data => {
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
            })
            .catch(error => {
                console.error('添加用户到组失败:', error);
                showMessage(error.message, 'error');
            });
        }
    });
    
    // 查看组成员（占位函数）
    window.viewGroupMembers = function(groupSam) {
        showMessage(`查看组 [${groupSam}] 的成员功能待实现`, 'info');
    };
    
    // 初始化
    checkConnectionStatus();
    
    // 定期检查连接状态
    setInterval(checkConnectionStatus, 30000); // 每30秒检查一次
});