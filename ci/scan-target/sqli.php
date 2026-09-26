<?php
// Deliberately vulnerable fixture (CWE-89). Never executed; scanned in CI only.
$conn = mysqli_connect("localhost", "user", "pass", "db");
$id = $_GET["id"];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = '" . $id . "'");
