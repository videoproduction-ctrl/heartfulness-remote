import Foundation

/// Where the running app bundle lives, to decide whether to offer "Move to Applications".
public enum AppPlacement {
    /// True if the bundle sits in /Applications or ~/Applications (or a subfolder of either).
    public static func isInApplicationsFolder(bundlePath: String, homeDirectory: String) -> Bool {
        let bundle = normalize(bundlePath)
        let home = normalize(homeDirectory)
        let roots = ["/Applications", home + "/Applications"]
        return roots.contains { root in bundle.hasPrefix(root + "/") }
    }

    /// Gatekeeper "App Translocation" runs quarantined apps from a random read-only path.
    public static func isTranslocated(bundlePath: String) -> Bool {
        bundlePath.contains("/AppTranslocation/")
    }

    /// Destination used by "Move to Applications": ~/Applications/<bundle name>.
    public static func destination(bundleName: String, homeDirectory: String) -> String {
        normalize(homeDirectory) + "/Applications/" + bundleName
    }

    private static func normalize(_ path: String) -> String {
        var p = (path as NSString).standardizingPath
        while p.count > 1 && p.hasSuffix("/") { p.removeLast() }
        return p
    }
}
