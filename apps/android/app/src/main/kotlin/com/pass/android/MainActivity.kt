package com.pass.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.pass.android.storage.AccountAssociationStore
import com.pass.android.vault.ItemSummary
import com.pass.android.vault.SaveItemResult
import com.pass.android.vault.UnlockResult
import com.pass.android.vault.VaultManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Single-Activity UI (no popup/background split — see VaultManager's doc
 * comment): login screen -> unlocked vault-list screen with a save form and
 * TOTP display. All secret state (VaultManager, its in-memory item cache,
 * the decrypted master password buffer) lives only in this process's
 * memory for the activity's lifetime; nothing survives process death
 * except the non-secret AccountAssociationStore entry.
 */
class MainActivity : ComponentActivity() {
    private lateinit var vaultManager: VaultManager
    private lateinit var associationStore: AccountAssociationStore

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        associationStore = AccountAssociationStore(applicationContext)
        vaultManager = VaultManager(
            deviceName = "pass-android",
            onAuthFailure = { runOnUiThread { /* handled via polling isUnlocked() in Compose state */ } },
        )

        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    AppRoot(vaultManager, associationStore)
                }
            }
        }
    }

    // D5: lock on any lifecycle stop that isn't a simple rotation — the
    // normal Android lifecycle already destroys this Activity's (and thus
    // VaultManager's in-memory) state on process death/eviction; an
    // explicit lock on `onStop` additionally covers "user backgrounds the
    // app" without waiting for the OS to actually kill the process.
    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations) {
            vaultManager.lock()
        }
    }
}

@Composable
fun AppRoot(vaultManager: VaultManager, associationStore: AccountAssociationStore) {
    var unlocked by remember { mutableStateOf(vaultManager.isUnlocked()) }
    if (!unlocked) {
        LoginScreen(vaultManager, associationStore) { unlocked = true }
    } else {
        VaultScreen(vaultManager) { unlocked = false }
    }
}

@Composable
fun LoginScreen(vaultManager: VaultManager, associationStore: AccountAssociationStore, onUnlocked: () -> Unit) {
    val saved = remember { associationStore.load() }
    var accountId by remember { mutableStateOf(saved?.accountId ?: "") }
    var apiOrigin by remember { mutableStateOf(saved?.apiOrigin ?: "") }
    var password by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScopeCompat()

    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Sign in", style = MaterialTheme.typography.headlineSmall)
        OutlinedTextField(value = accountId, onValueChange = { accountId = it }, label = { Text("Account ID") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(value = apiOrigin, onValueChange = { apiOrigin = it }, label = { Text("API origin (https://...)") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Master password") },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth(),
        )
        if (error != null) Text(error!!, color = MaterialTheme.colorScheme.error)
        Button(enabled = !busy, onClick = {
            busy = true
            error = null
            scope.launch {
                val passwordBytes = password.toByteArray(Charsets.UTF_8)
                val result = withContext(Dispatchers.IO) { vaultManager.unlock(accountId, apiOrigin, passwordBytes) }
                password = ""
                busy = false
                when (result) {
                    is UnlockResult.Ok -> {
                        associationStore.save(AccountAssociationStore.Association(accountId, apiOrigin))
                        onUnlocked()
                    }
                    is UnlockResult.Failed -> error = "Sign-in failed. Check your account, origin, and password."
                }
            }
        }, modifier = Modifier.fillMaxWidth()) {
            Text(if (busy) "Signing in..." else "Unlock")
        }
    }
}

@Composable
fun VaultScreen(vaultManager: VaultManager, onLocked: () -> Unit) {
    var items by remember { mutableStateOf(vaultManager.listItems()) }
    var title by remember { mutableStateOf("") }
    var username by remember { mutableStateOf("") }
    var passwordField by remember { mutableStateOf("") }
    var saveError by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScopeCompat()

    Scaffold { padding ->
        Column(Modifier.fillMaxSize().padding(padding).padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Vault", style = MaterialTheme.typography.headlineSmall)
            Button(onClick = { vaultManager.lock(); onLocked() }) { Text("Lock") }

            OutlinedTextField(value = title, onValueChange = { title = it }, label = { Text("Title") }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(value = username, onValueChange = { username = it }, label = { Text("Username") }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(
                value = passwordField,
                onValueChange = { passwordField = it },
                label = { Text("Password") },
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
            )
            if (saveError != null) Text(saveError!!, color = MaterialTheme.colorScheme.error)
            Button(onClick = {
                scope.launch {
                    val result = withContext(Dispatchers.IO) {
                        vaultManager.saveItem(
                            VaultManager.SaveItemInput(type = "login", title = title, username = username, password = passwordField),
                        )
                    }
                    when (result) {
                        is SaveItemResult.Ok -> {
                            title = ""; username = ""; passwordField = ""; saveError = null
                            items = withContext(Dispatchers.IO) { vaultManager.listItems() }
                        }
                        is SaveItemResult.Failed -> saveError = result.reason
                    }
                }
            }, modifier = Modifier.fillMaxWidth()) { Text("Save item") }

            LazyColumn(modifier = Modifier.fillMaxWidth()) {
                items(items) { item: ItemSummary ->
                    Card(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                        Column(Modifier.padding(12.dp)) {
                            Text(item.title, style = MaterialTheme.typography.titleMedium)
                            if (!item.username.isNullOrEmpty()) Text(item.username)
                            if (item.type == "totp-login") {
                                val totp = vaultManager.getTotp(item.itemId)
                                if (totp != null) Text("TOTP: ${totp.code} (${totp.secondsRemaining}s)")
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun rememberCoroutineScopeCompat() = androidx.compose.runtime.rememberCoroutineScope()
