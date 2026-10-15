package com.example.integrityprobe

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.PathParser
import androidx.compose.ui.unit.dp

/** Only the ten small, locally drawn symbols used by this app; no icon catalog dependency. */
internal object ProbeIcons {
    private fun icon(name: String, path: String): ImageVector = ImageVector.Builder(
        name = name, defaultWidth = 24.dp, defaultHeight = 24.dp,
        viewportWidth = 24f, viewportHeight = 24f
    ).addPath(
        pathData = PathParser().parsePathString(path).toNodes(),
        fill = null, stroke = SolidColor(Color.Black), strokeLineWidth = 1.8f,
        strokeLineCap = StrokeCap.Round, strokeLineJoin = StrokeJoin.Round
    ).build()

    val Shield by lazy { icon("Shield", "M12 3L4 6V11C4 16 7 19 12 22C17 19 20 16 20 11V6Z M8 12L11 15L16 9") }
    val Key by lazy { icon("Key", "M10 8C10 5 8 3 5 3C2 3 1 5 1 8C1 11 3 13 6 13C8 13 10 11 10 8Z M10 8H22V12H18V15H15V11H10 M5 7V9") }
    val Document by lazy { icon("Document", "M5 3H14L19 8V21H5Z M14 3V8H19 M8 12H16 M8 16H16") }
    val Flask by lazy { icon("Flask", "M9 3H15 M10 3V10L4 20C4 21 5 21 6 21H18C19 21 20 21 20 20L14 10V3 M7 15H17") }
    val Play by lazy { icon("Play", "M8 4L20 12L8 20Z") }
    val Checklist by lazy { icon("Checklist", "M4 3H20V21H4Z M7 8L8 9L10 6 M13 8H17 M7 15L8 16L10 13 M13 15H17") }
    val Refresh by lazy { icon("Refresh", "M20 10C19 6 16 4 12 4C8 4 4 7 4 12C4 17 8 20 12 20C15 20 18 18 19 16 M20 4V10H14") }
    val Warning by lazy { icon("Warning", "M12 3L2 21H22Z M12 9V14 M12 17V18") }
    val Info by lazy { icon("Info", "M21 12C21 7 17 3 12 3C7 3 3 7 3 12C3 17 7 21 12 21C17 21 21 17 21 12Z M12 11V17 M12 7V8") }
    val Copy by lazy { icon("Copy", "M9 8H21V21H9Z M5 16H3V3H15V5") }
}
