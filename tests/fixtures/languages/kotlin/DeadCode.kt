package Demo.Dead

object DeadCode {
    fun unusedMethod(): String {
        return "never called"
    }

    const val UNUSED = "dead"
}
