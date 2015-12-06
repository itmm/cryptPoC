window.addEventListener('load', function () {
	'use strict';

	function $(id) { return document.getElementById(id); }
	function moveClass(from, to, cls) {
		from.classList.remove(cls);
		to.classList.add(cls);
	}

	var encryptTab = $('encrypt-tab');
	var decryptTab = $('decrypt-tab');
	var encryptContent = $('encrypt-content');
	var decryptContent = $('decrypt-content');
	var encryptPassword = $('encrypt-password');
	var decryptPassword = $('decrypt-password');
	var encryptSource = $('encrypt-source');
	var decryptSource = $('decrypt-source');

	function switchToEncryptTab(evt) {
		moveClass(decryptTab, encryptTab, 'active');
		moveClass(encryptContent, decryptContent, 'hidden');
		evt && evt.preventDefault();
	}
	function switchToDecryptTab(evt) {
		moveClass(encryptTab, decryptTab, 'active');
		moveClass(decryptContent, encryptContent, 'hidden');
		evt && evt.preventDefault();
	}

	encryptTab.addEventListener('click', switchToEncryptTab);
	decryptTab.addEventListener('click', switchToDecryptTab);
	$('do-encrypt').addEventListener('click', function(evt) {
		var password = encryptPassword.value;
		var encrypted = encrypt_string(password, encryptSource.value);
		decryptPassword.value = password;
		decryptSource.value = encrypted;
		switchToDecryptTab();
		evt.preventDefault();
	});
	$('do-decrypt').addEventListener('click', function(evt) {
		var password = decryptPassword.value;
		var decrypted = decrypt_string(password, decryptSource.value);
		encryptPassword.value = password;
		encryptSource.value = decrypted;
		switchToEncryptTab();
		evt.preventDefault();
	});
});