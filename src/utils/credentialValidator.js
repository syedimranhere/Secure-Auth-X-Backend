export const isValidPassword = (password) => {
  const bannedPasswords = [
    "123456",
    "password",
    "qwerty",
    "123456789",
    "111111",
    "abc123",
    "123123",
  ];
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasDigit = /\d/.test(password);
  const isLengthValid = password.length >= 8;
  return (
    isLengthValid &&
    hasUpper &&
    hasLower &&
    hasDigit &&
    !bannedPasswords.includes(password.toLowerCase())
  );
};
export const isValidUsername = (username) => {
  const hasSpecialChars = /[!@#$%^&*(),.?":{}|<>]/.test(username);
  const isLengthValid = username.length >= 3 && username.length <= 20;
  return isLengthValid && !hasSpecialChars;
};
