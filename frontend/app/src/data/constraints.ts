export class Constraints {
  static MAX_MILISECONDS_DELAY = Math.pow(2, 31) - 1;
  static MAX_SECONDS_DELAY = Math.floor(
    Constraints.MAX_MILISECONDS_DELAY / 1000
  );
  static MAX_MINUTES_DELAY = Math.floor(
    Constraints.MAX_MILISECONDS_DELAY / (1000 * 60)
  );
  static MAX_HOURS_DELAY = Math.floor(
    Constraints.MAX_MILISECONDS_DELAY / (1000 * 60 * 60)
  );
  static MAX_DAYS_DELAY = Math.floor(
    Constraints.MAX_MILISECONDS_DELAY / (1000 * 60 * 60 * 24)
  );
  static MAX_WEEKS_DELAY = Math.floor(
    Constraints.MAX_MILISECONDS_DELAY / (1000 * 60 * 60 * 24 * 7)
  );
}
