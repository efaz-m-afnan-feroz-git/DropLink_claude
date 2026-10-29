package app.droplink

import android.app.Application
import app.droplink.di.AppContainer
import app.droplink.service.Notifications

class DropLinkApp : Application() {
    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        container = AppContainer(this)
        Notifications.ensureChannels(this)
    }
}
