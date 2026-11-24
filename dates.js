// How a date reads in the record tables: "Jan 1, 2027". Records keep dates as "YYYY-MM-DD", which is also what the date
// fields, sorting, CSV and filters use; only what the tables show changes. Anything that isn't a date is shown as it is.
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

export function tableDate(value) {
  const text = String(value ?? "");
  const match = text.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  const month = match ? MONTHS[Number(match[2]) - 1] : undefined;
  return month ? `${month} ${Number(match[3])}, ${match[1]}` : text;
}
