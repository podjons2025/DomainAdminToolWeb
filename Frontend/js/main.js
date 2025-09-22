document.addEventListener('DOMContentLoaded', function() {
    // DOMԪ������
    const connectionForm = document.getElementById('connection-form');
    const connectBtn = document.getElementById('connect-btn');
    const disconnectBtn = document.getElementById('disconnect-btn');
    const connectionStatus = document.getElementById('connection-status');
    const userCountElem = document.getElementById('user-count');
    const groupCountElem = document.getElementById('group-count');
    const currentOuDisplay = document.getElementById('current-ou-display');
    
    // �������
    const connectionPanel = document.getElementById('connection-panel');
    const ouPanel = document.getElementById('ou-panel');
    const userPanel = document.getElementById('user-panel');
    const groupPanel = document.getElementById('group-panel');
    
    // ��Ϣ������
    const messageBox = document.getElementById('message-box');
    const messageContent = document.getElementById('message-content');
    const closeMessage = document.getElementById('close-message');
    
    // OU���Ԫ��
    const switchOuBtn = document.getElementById('switch-ou-btn');
    const createOuBtn = document.getElementById('create-ou-btn');
    const newOuName = document.getElementById('new-ou-name');
    const ouDialog = document.getElementById('ou-dialog');
    const ouSelect = document.getElementById('ou-select');
    const confirmOu = document.getElementById('confirm-ou');
    const cancelOu = document.getElementById('cancel-ou');
    
    // �û����Ԫ��
    const userSearch = document.getElementById('user-search');
    const refreshUsersBtn = document.getElementById('refresh-users-btn');
    const toggleUserFormBtn = document.getElementById('toggle-user-form-btn');
    const userForm = document.getElementById('user-form');
    const cancelUserBtn = document.getElementById('cancel-user-btn');
    const usersBody = document.getElementById('users-body');
    
    // �����Ԫ��
    const groupSearch = document.getElementById('group-search');
    const refreshGroupsBtn = document.getElementById('refresh-groups-btn');
    const toggleGroupFormBtn = document.getElementById('toggle-group-form-btn');
    const groupForm = document.getElementById('group-form');
    const cancelGroupBtn = document.getElementById('cancel-group-btn');
    const groupsBody = document.getElementById('groups-body');
    const addUsersToGroupBtn = document.getElementById('add-users-to-group-btn');
    
    // ȫ��״̬
    let isConnected = false;
    let selectedGroup = null;
    let selectedUsers = [];
    
    // ��ʾ��Ϣ
    function showMessage(text, type = 'info') {
        messageContent.textContent = text;
        messageBox.className = 'message-box';
        messageBox.classList.add(type);
        
        // 5����Զ��ر�
        setTimeout(() => {
            messageBox.classList.add('hidden');
        }, 5000);
    }
    
    // �ر���Ϣ
    closeMessage.addEventListener('click', () => {
        messageBox.classList.add('hidden');
    });
    
    // �������״̬
    function checkConnectionStatus() {
        fetch('/api/connection-status')
            .then(response => response.json())
            .then(data => {
                isConnected = data.isConnected;
                connectionStatus.textContent = data.status;
                userCountElem.textContent = `�û���: ${data.userCount}`;
                groupCountElem.textContent = `����: ${data.groupCount}`;
                
                if (data.currentOU) {
                    currentOuDisplay.textContent = data.currentOU;
                }
                
                // ����UI״̬
                if (isConnected) {
                    connectBtn.disabled = true;
                    disconnectBtn.disabled = false;
                    ouPanel.style.display = 'block';
                    userPanel.style.display = 'block';
                    groupPanel.style.display = 'block';
                    
                    // ��������
                    loadUsers();
                    loadGroups();
                } else {
                    connectBtn.disabled = false;
                    disconnectBtn.disabled = true;
                    ouPanel.style.display = 'none';
                    userPanel.style.display = 'none';
                    groupPanel.style.display = 'none';
                    
                    // ��ձ��
                    usersBody.innerHTML = '<tr><td colspan="8" class="empty-state">�������ӵ��򲢼����û�</td></tr>';
                    groupsBody.innerHTML = '<tr><td colspan="4" class="empty-state">�������ӵ��򲢼�����</td></tr>';
                }
            })
            .catch(error => {
                console.error('�������״̬ʧ��:', error);
                showMessage('�������״̬ʧ��', 'error');
            });
    }
    
    // ���ӵ���
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
                    throw new Error(data.message || '����ʧ��');
                });
            }
            return response.json();
        })
        .then(data => {
            showMessage('���ӳɹ�', 'success');
            currentOuDisplay.textContent = data.currentOU;
            checkConnectionStatus();
        })
        .catch(error => {
            console.error('����ʧ��:', error);
            showMessage(error.message, 'error');
        });
    });
    
    // �Ͽ�����
    disconnectBtn.addEventListener('click', function() {
        if (confirm('ȷ��Ҫ�Ͽ������������')) {
            fetch('/api/disconnect', {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                showMessage('�ѳɹ��Ͽ�����', 'success');
                checkConnectionStatus();
            })
            .catch(error => {
                console.error('�Ͽ�����ʧ��:', error);
                showMessage('�Ͽ�����ʧ��', 'error');
            });
        }
    });
    
    // ����OU�б�
    function loadOUs() {
        fetch('/api/ous')
            .then(response => {
                if (!response.ok) {
                    return response.json().then(data => {
                        throw new Error(data.message || '��ȡOU�б�ʧ��');
                    });
                }
                return response.json();
            })
            .then(data => {
                // ���ѡ���
                ouSelect.innerHTML = '';
                
                // ���OUѡ��
                data.ous.forEach(ou => {
                    const option = document.createElement('option');
                    option.value = ou.DistinguishedName;
                    option.textContent = ou.Name;
                    option.dataset.name = ou.Name;
                    ouSelect.appendChild(option);
                });
                
                // ��ʾ�Ի���
                ouDialog.classList.remove('hidden');
            })
            .catch(error => {
                console.error('����OU�б�ʧ��:', error);
                showMessage(error.message, 'error');
            });
    }
    
    // �л�OU��ť
    switchOuBtn.addEventListener('click', loadOUs);
    
    // ȷ��ѡ��OU
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
                        throw new Error(data.message || '�л�OUʧ��');
                    });
                }
                return response.json();
            })
            .then(data => {
                showMessage('���л���: ' + ouName, 'success');
                currentOuDisplay.textContent = data.currentOU;
                userCountElem.textContent = `�û���: ${data.userCount}`;
                groupCountElem.textContent = `����: ${data.groupCount}`;
                
                // ���¼����û�����
                loadUsers();
                loadGroups();
                
                // �رնԻ���
                ouDialog.classList.add('hidden');
            })
            .catch(error => {
                console.error('�л�OUʧ��:', error);
                showMessage(error.message, 'error');
            });
        }
    });
    
    // ȡ��ѡ��OU
    cancelOu.addEventListener('click', function() {
        ouDialog.classList.add('hidden');
    });
    
    // ����OU
    createOuBtn.addEventListener('click', function() {
        const ouName = newOuName.value.trim();
        if (!ouName) {
            showMessage('������OU����', 'error');
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
                    throw new Error(data.message || '����OUʧ��');
                });
            }
            return response.json();
        })
        .then(data => {
            showMessage('OU�����ɹ�', 'success');
            newOuName.value = '';
            loadOUs(); // ���¼���OU�б�
        })
        .catch(error => {
            console.error('����OUʧ��:', error);
            showMessage(error.message, 'error');
        });
    });
    
    // �����û��б�
    function loadUsers() {
        fetch('/api/users')
            .then(response => {
                if (!response.ok) {
                    return response.json().then(data => {
                        throw new Error(data.message || '��ȡ�û��б�ʧ��');
                    });
                }
                return response.json();
            })
            .then(data => {
                renderUsersTable(data.users);
                userCountElem.textContent = `�û���: ${data.count}`;
            })
            .catch(error => {
                console.error('�����û�ʧ��:', error);
                showMessage(error.message, 'error');
            });
    }
    
    // ��Ⱦ�û����
    function renderUsersTable(users) {
        usersBody.innerHTML = '';
        
        if (users.length === 0) {
            usersBody.innerHTML = '<tr><td colspan="8" class="empty-state">û���ҵ��û�</td></tr>';
            return;
        }
        
        users.forEach(user => {
            const row = document.createElement('tr');
            row.dataset.sam = user.SamAccountName;
            
            // ������л�ѡ��״̬
            row.addEventListener('click', function(e) {
                // ���������ǰ�ť��������ѡ��
                if (e.target.tagName === 'BUTTON') return;
                
                row.classList.toggle('selected');
                
                // ����ѡ���û��б�
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
                        ${user.Enabled ? '����' : '����'}
                    </span>
                </td>
                <td class="action-buttons">
                    <button class="btn ${user.Enabled ? 'danger' : 'primary'}" 
                            onclick="toggleUserStatus('${user.SamAccountName}', ${!user.Enabled})">
                        ${user.Enabled ? '����' : '����'}
                    </button>
                </td>
            `;
            
            usersBody.appendChild(row);
        });
    }
    
    // ˢ���û��б�
    refreshUsersBtn.addEventListener('click', loadUsers);
    
    // �����û�
    userSearch.addEventListener('input', function() {
        const filter = this.value.trim();
        
        fetch(`/api/users/filter?filter=${encodeURIComponent(filter)}`)
            .then(response => {
                if (!response.ok) {
                    return response.json().then(data => {
                        throw new Error(data.message || '�����û�ʧ��');
                    });
                }
                return response.json();
            })
            .then(data => {
                renderUsersTable(data.users);
            })
            .catch(error => {
                console.error('�����û�ʧ��:', error);
                showMessage(error.message, 'error');
            });
    });
    
    // �л��û�����ʾ
    toggleUserFormBtn.addEventListener('click', function() {
        userForm.style.display = userForm.style.display === 'none' ? 'block' : 'none';
    });
    
    // ȡ�������û�
    cancelUserBtn.addEventListener('click', function() {
        userForm.reset();
        userForm.style.display = 'none';
    });
    
    // �����û�
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
        
        // �ͻ�����֤
        if (!cnName || !username || !password || !confirmPassword) {
            showMessage('����д�����ֶ�', 'error');
            return;
        }
        
        if (password !== confirmPassword) {
            showMessage('������������벻һ��', 'error');
            return;
        }
        
        if (password.length < 8 || 
            !/[A-Z]/.test(password) || 
            !/[a-z]/.test(password) || 
            !/[0-9]/.test(password) || 
            !/[^a-zA-Z0-9]/.test(password)) {
            showMessage('�����������8λ��������Сд��ĸ�����ֺ������ַ�', 'error');
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
                    throw new Error(data.message || '�����û�ʧ��');
                });
            }
            return response.json();
        })
        .then(data => {
            showMessage('�û������ɹ�', 'success');
            userForm.reset();
            userForm.style.display = 'none';
            loadUsers();
            userCountElem.textContent = `�û���: ${data.userCount}`;
        })
        .catch(error => {
            console.error('�����û�ʧ��:', error);
            showMessage(error.message, 'error');
        });
    });
    
    // �л��û�״̬������/���ã�
    window.toggleUserStatus = function(username, newState) {
        const action = newState ? '����' : '����';
        if (confirm(`ȷ��Ҫ${action}�û� [${username}] ��`)) {
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
                        throw new Error(data.message || `${action}�û�ʧ��`);
                    });
                }
                return response.json();
            })
            .then(data => {
                showMessage(data.message, 'success');
                loadUsers();
            })
            .catch(error => {
                console.error(`${action}�û�ʧ��:`, error);
                showMessage(error.message, 'error');
            });
        }
    };
    
    // �������б�
    function loadGroups() {
        fetch('/api/groups')
            .then(response => {
                if (!response.ok) {
                    return response.json().then(data => {
                        throw new Error(data.message || '��ȡ���б�ʧ��');
                    });
                }
                return response.json();
            })
            .then(data => {
                renderGroupsTable(data.groups);
                groupCountElem.textContent = `����: ${data.count}`;
            })
            .catch(error => {
                console.error('������ʧ��:', error);
                showMessage(error.message, 'error');
            });
    }
    
    // ��Ⱦ����
    function renderGroupsTable(groups) {
        groupsBody.innerHTML = '';
        selectedGroup = null;
        addUsersToGroupBtn.disabled = true;
        
        if (groups.length === 0) {
            groupsBody.innerHTML = '<tr><td colspan="4" class="empty-state">û���ҵ���</td></tr>';
            return;
        }
        
        groups.forEach(group => {
            const row = document.createElement('tr');
            row.dataset.sam = group.SamAccountName;
            
            // �����ѡ����
            row.addEventListener('click', function() {
                // �Ƴ������е�ѡ��״̬
                document.querySelectorAll('#groups-table tbody tr.selected').forEach(r => {
                    r.classList.remove('selected');
                });
                
                // ��ӵ�ǰ�е�ѡ��״̬
                row.classList.add('selected');
                selectedGroup = group.SamAccountName;
                
                // ���°�ť״̬
                addUsersToGroupBtn.disabled = selectedUsers.length === 0;
            });
            
            row.innerHTML = `
                <td>${group.Name}</td>
                <td>${group.SamAccountName}</td>
                <td>${group.Description || '-'}</td>
                <td class="action-buttons">
                    <button class="btn secondary" onclick="viewGroupMembers('${group.SamAccountName}')">
                        ��Ա
                    </button>
                </td>
            `;
            
            groupsBody.appendChild(row);
        });
    }
    
    // ˢ�����б�
    refreshGroupsBtn.addEventListener('click', loadGroups);
    
    // ������
    groupSearch.addEventListener('input', function() {
        const filter = this.value.trim();
        
        fetch(`/api/groups/filter?filter=${encodeURIComponent(filter)}`)
            .then(response => {
                if (!response.ok) {
                    return response.json().then(data => {
                        throw new Error(data.message || '������ʧ��');
                    });
                }
                return response.json();
            })
            .then(data => {
                renderGroupsTable(data.groups);
            })
            .catch(error => {
                console.error('������ʧ��:', error);
                showMessage(error.message, 'error');
            });
    });
    
    // �л������ʾ
    toggleGroupFormBtn.addEventListener('click', function() {
        groupForm.style.display = groupForm.style.display === 'none' ? 'block' : 'none';
    });
    
    // ȡ��������
    cancelGroupBtn.addEventListener('click', function() {
        groupForm.reset();
        groupForm.style.display = 'none';
    });
    
    // ������
    groupForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const groupName = document.getElementById('group-name').value.trim();
        const groupSam = document.getElementById('group-sam').value.trim();
        const groupDescription = document.getElementById('group-description').value.trim();
        
        // �ͻ�����֤
        if (!groupName || !groupSam) {
            showMessage('�����ƺ����˺Ų���Ϊ��', 'error');
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
                    throw new Error(data.message || '������ʧ��');
                });
            }
            return response.json();
        })
        .then(data => {
            showMessage('�鴴���ɹ�', 'success');
            groupForm.reset();
            groupForm.style.display = 'none';
            loadGroups();
            groupCountElem.textContent = `����: ${data.groupCount}`;
        })
        .catch(error => {
            console.error('������ʧ��:', error);
            showMessage(error.message, 'error');
        });
    });
    
    // ����ѡ�е��û��б�
    function updateSelectedUsers() {
        selectedUsers = [];
        document.querySelectorAll('#users-table tbody tr.selected').forEach(row => {
            selectedUsers.push(row.dataset.sam);
        });
        
        // ��������û����鰴ť״̬
        addUsersToGroupBtn.disabled = selectedUsers.length === 0 || !selectedGroup;
    }
    
    // ����û�����
    addUsersToGroupBtn.addEventListener('click', function() {
        if (!selectedGroup || selectedUsers.length === 0) {
            showMessage('����ѡ��һ���������һ���û�', 'error');
            return;
        }
        
        if (confirm(`ȷ��Ҫ�� ${selectedUsers.length} ���û���ӵ��� [${selectedGroup}] ��`)) {
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
                        throw new Error(data.message || '����û�����ʧ��');
                    });
                }
                return response.json();
            })
            .then(data => {
                showMessage(data.message, 'success');
                
                // ȡ��ѡ��
                document.querySelectorAll('#users-table tbody tr.selected').forEach(row => {
                    row.classList.remove('selected');
                });
                document.querySelectorAll('#groups-table tbody tr.selected').forEach(row => {
                    row.classList.remove('selected');
                });
                
                selectedUsers = [];
                selectedGroup = null;
                addUsersToGroupBtn.disabled = true;
                
                // ˢ���û��б�����ʾ���º������Ϣ
                loadUsers();
            })
            .catch(error => {
                console.error('����û�����ʧ��:', error);
                showMessage(error.message, 'error');
            });
        }
    });
    
    // �鿴���Ա��ռλ������
    window.viewGroupMembers = function(groupSam) {
        showMessage(`�鿴�� [${groupSam}] �ĳ�Ա���ܴ�ʵ��`, 'info');
    };
    
    // ��ʼ��
    checkConnectionStatus();
    
    // ���ڼ������״̬
    setInterval(checkConnectionStatus, 30000); // ÿ30����һ��
});