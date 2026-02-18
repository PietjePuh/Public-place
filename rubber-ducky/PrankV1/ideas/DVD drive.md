while ($true) {
    (New-Object -comObject WMPlayer.OCX.7).cdromCollection.Item(0).Eject()
    Start-Sleep -Seconds 5
}
