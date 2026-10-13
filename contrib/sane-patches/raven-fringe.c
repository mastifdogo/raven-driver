/* raven-driver: colour fringe (misregistration) correction for the Raven Compact.
 *
 * The Compact lights red, green and blue in turn while the paper moves, so
 * each colour sees the page a fraction of a line further on. Black-and-white
 * edges across the feed direction get coloured fringes. This shifts red and
 * blue down or up the page to line them up with green.
 *
 * Profile: text lines "<dpi> <red offset> <blue offset>", offsets in pixels
 * down the page relative to green, as contrib/measure-color-fringe.py --save
 * writes them. The entry for the scan's resolution is used, else the nearest
 * one. Looked up in $RAVEN_FRINGE ("off" or empty disables), then
 * $XDG_CONFIG_HOME/raven-driver/fringe.txt, ~/.config/raven-driver/fringe.txt,
 * /etc/sane.d/raven-compact-fringe.txt.
 *
 * Data streams in without lookahead, so all three channels are shifted by
 * the same extra amount until every one only needs the current and previous
 * line: each output sample is (1 - a) * this line + a * previous line, with
 * 0 <= a <= 1. The whole image moves by under one line, which is invisible.
 * Only 8-bit RGB scans are changed.
 */

static int raven_fr_ready = 0;
static int raven_fr_active = 0;
static int raven_fr_first = 1;          /* no previous line yet */
static SANE_Int raven_fr_bpl = 0;
static SANE_Int raven_fr_pix_bytes = 0; /* bytes holding pixels in a line */
static SANE_Int raven_fr_pos = 0;
static int raven_fr_weight[3];          /* a * 256 for red, green, blue */
static SANE_Byte* raven_fr_prev = NULL; /* previous raw line */
static SANE_Byte* raven_fr_cur = NULL;  /* current raw line, being filled */

static void
raven_fr_reset (void)
{
  raven_fr_ready = 0;
  raven_fr_active = 0;
  raven_fr_first = 1;
  raven_fr_pos = 0;
}

static FILE*
raven_fr_open (void)
{
  const char* env = getenv ("RAVEN_FRINGE");
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
    snprintf (path, sizeof (path), "%s/raven-driver/fringe.txt", home);
    if ((f = fopen (path, "r")))
      return f;
  }
  home = getenv ("HOME");
  if (home && *home) {
    snprintf (path, sizeof (path), "%s/.config/raven-driver/fringe.txt", home);
    if ((f = fopen (path, "r")))
      return f;
  }
  return fopen ("/etc/sane.d/raven-compact-fringe.txt", "r");
}

static void
raven_fr_build (SANE_Parameters* p, double res)
{
  char line[256];
  double red, blue, best = -1, shift[3], top;
  int c, found = 0;
  FILE* f;

  raven_fr_ready = 1;
  raven_fr_active = 0;
  if (p->format != SANE_FRAME_RGB || p->depth != 8 || p->bytes_per_line < 3)
    return;
  if (!(f = raven_fr_open ()))
    return;
  while (fgets (line, sizeof (line), f)) {
    double d;
    if (line[0] == '#')
      continue;
    if (sscanf (line, "%lf %lf %lf", &d, &red, &blue) != 3)
      continue;
    if (!found || fabs (d - res) < fabs (best - res)) {
      best = d;
      shift[0] = red;
      shift[2] = blue;
      found = 1;
    }
  }
  fclose (f);
  if (!found)
    return;

  /* Sample channel c at (this line + shift[c]); move every shift down by the
     largest one so none looks ahead, then clamp to one line back. */
  shift[1] = 0;
  top = shift[0];
  if (shift[1] > top) top = shift[1];
  if (shift[2] > top) top = shift[2];
  for (c = 0; c < 3; c++) {
    double a = top - shift[c];
    if (a < 0) a = 0;
    if (a > 1) a = 1;
    raven_fr_weight[c] = (int) (a * 256 + 0.5);
  }

  free (raven_fr_prev);
  free (raven_fr_cur);
  raven_fr_bpl = p->bytes_per_line;
  raven_fr_pix_bytes = p->pixels_per_line * 3;
  if (raven_fr_pix_bytes > raven_fr_bpl)
    raven_fr_pix_bytes = raven_fr_bpl;
  raven_fr_prev = malloc ((size_t) raven_fr_bpl);
  raven_fr_cur = malloc ((size_t) raven_fr_bpl);
  if (!raven_fr_prev || !raven_fr_cur)
    return;
  raven_fr_first = 1;
  raven_fr_pos = 0;
  raven_fr_active = 1;
  DBG (1, "raven: colour fringe correction on (%g dpi entry: red %+.3f, blue %+.3f)\n",
       best, shift[0], shift[2]);
}

static void
raven_fr_apply (SANE_Byte* buf, long len)
{
  long i;
  if (!raven_fr_active || len <= 0)
    return;
  for (i = 0; i < len; i++) {
    SANE_Int pos = raven_fr_pos;
    SANE_Byte raw = buf[i];
    raven_fr_cur[pos] = raw;
    if (!raven_fr_first && pos < raven_fr_pix_bytes) {
      int a = raven_fr_weight[pos % 3];
      buf[i] = (SANE_Byte) ((raw * (256 - a) + raven_fr_prev[pos] * a + 128) >> 8);
    }
    if (++raven_fr_pos >= raven_fr_bpl) {
      SANE_Byte* t = raven_fr_prev;
      raven_fr_prev = raven_fr_cur;
      raven_fr_cur = t;
      raven_fr_pos = 0;
      raven_fr_first = 0;
    }
  }
}
