/* raven-driver: flat-field (shading) correction for the Raven Compact.
 *
 * The Compact reads darker toward the ends of its sensor, and its firmware
 * offers no calibration data to the backend. This multiplies every 8-bit
 * sample by a gain for its position across the page, taken from a profile
 * that contrib/calibrate-flatfield.sh makes from a scan of a blank sheet.
 *
 * Profile: text lines "<inches from left> <red> <green> <blue> <gray>", in
 * increasing order; '#' lines are comments. Looked up in $RAVEN_FLATFIELD
 * ("off" or empty disables), then $XDG_CONFIG_HOME/raven-driver/flatfield.txt,
 * ~/.config/raven-driver/flatfield.txt, /etc/sane.d/raven-compact-flatfield.txt.
 *
 * Inserted into avision.c before sane_read(); needs raven_quirks, which is
 * set while a Raven Compact is open.
 */

#define RAVEN_FF_MAX 20000

static int raven_ff_ready = 0;          /* profile looked at for this scan */
static int raven_ff_active = 0;         /* correction is being applied */
static SANE_Int raven_ff_bpl = 0;       /* bytes per line */
static SANE_Int raven_ff_pos = 0;       /* byte position within the line */
static unsigned short* raven_ff_gain = NULL; /* gain * 256 per byte of a line */

static void
raven_ff_reset (void)
{
  raven_ff_ready = 0;
  raven_ff_active = 0;
  raven_ff_pos = 0;
}

static FILE*
raven_ff_open (void)
{
  const char* env = getenv ("RAVEN_FLATFIELD");
  const char* home;
  char path[1024];
  FILE* f;

  if (env) {
    if (!*env || strcmp (env, "off") == 0)
      return NULL;
    return fopen (env, "r");
  }
  home = getenv ("XDG_CONFIG_HOME");
  if (home && *home) {
    snprintf (path, sizeof (path), "%s/raven-driver/flatfield.txt", home);
    if ((f = fopen (path, "r")))
      return f;
  }
  home = getenv ("HOME");
  if (home && *home) {
    snprintf (path, sizeof (path), "%s/.config/raven-driver/flatfield.txt", home);
    if ((f = fopen (path, "r")))
      return f;
  }
  return fopen ("/etc/sane.d/raven-compact-flatfield.txt", "r");
}

/* Build the per-byte gain table for the current scan. */
static void
raven_ff_build (SANE_Parameters* p, double res, double left_inch)
{
  static double pos[RAVEN_FF_MAX];
  static double gain[RAVEN_FF_MAX][4];
  char line[256];
  int n = 0, channels, x, c, k = 0;
  FILE* f;

  raven_ff_ready = 1;
  raven_ff_active = 0;
  if (p->depth != 8 || res <= 0)
    return;
  if (p->format == SANE_FRAME_RGB)
    channels = 3;
  else if (p->format == SANE_FRAME_GRAY)
    channels = 1;
  else
    return;
  if (!(f = raven_ff_open ()))
    return;
  while (n < RAVEN_FF_MAX && fgets (line, sizeof (line), f)) {
    if (line[0] == '#')
      continue;
    if (sscanf (line, "%lf %lf %lf %lf %lf", &pos[n], &gain[n][0],
                &gain[n][1], &gain[n][2], &gain[n][3]) == 5)
      n++;
  }
  fclose (f);
  if (n < 2 || p->bytes_per_line <= 0)
    return;

  free (raven_ff_gain);
  raven_ff_bpl = p->bytes_per_line;
  raven_ff_gain = malloc (sizeof (unsigned short) * (size_t) raven_ff_bpl);
  if (!raven_ff_gain)
    return;
  for (x = 0; x < raven_ff_bpl; x++)
    raven_ff_gain[x] = 256;           /* padding bytes stay unchanged */

  for (x = 0; x < p->pixels_per_line && x * channels < raven_ff_bpl; x++) {
    double inch = left_inch + (x + 0.5) / res;
    double t;
    while (k > 0 && pos[k] > inch)
      k--;
    while (k < n - 2 && pos[k + 1] < inch)
      k++;
    t = (inch - pos[k]) / (pos[k + 1] - pos[k]);
    if (t < 0) t = 0;
    if (t > 1) t = 1;
    for (c = 0; c < channels; c++) {
      int col = channels == 3 ? c : 3;
      double g = gain[k][col] + t * (gain[k + 1][col] - gain[k][col]);
      if (g < 0.5) g = 0.5;
      if (g > 2.0) g = 2.0;
      raven_ff_gain[x * channels + c] = (unsigned short) (g * 256 + 0.5);
    }
  }
  raven_ff_pos = 0;
  raven_ff_active = 1;
  DBG (1, "raven: flat-field correction on (%d profile points)\n", n);
}

static void
raven_ff_apply (SANE_Byte* buf, long len)
{
  long i;
  if (!raven_ff_active || len <= 0)
    return;
  for (i = 0; i < len; i++) {
    unsigned v = (buf[i] * raven_ff_gain[raven_ff_pos] + 128) >> 8;
    buf[i] = (SANE_Byte) (v > 255 ? 255 : v);
    if (++raven_ff_pos >= raven_ff_bpl)
      raven_ff_pos = 0;
  }
}
