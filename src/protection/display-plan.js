function buildDisplayProtectionPlan(screen) {
  const displays = screen.getAllDisplays();
  const primaryDisplay = screen.getPrimaryDisplay();
  // Only secondary displays receive black overlays. The primary display stays
  // reserved for the real exam window.
  const secondaryDisplays = displays.filter((display) => display.id !== primaryDisplay.id);

  return {
    displays,
    primaryDisplay,
    secondaryDisplays,
    activeMonitorCount: displays.length,
    blackOverlayCount: secondaryDisplays.length,
  };
}

module.exports = {
  buildDisplayProtectionPlan,
};
