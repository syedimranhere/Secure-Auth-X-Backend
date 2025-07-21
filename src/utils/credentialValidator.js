export const isValidUsername = (username) => {
  const bannedPatterns = [
    /^[a-z]{10,}$/,               // All lowercase gibberish
    /(.)\1{3,}/,                  // Repeated characters like "aaaabbbb"
    /\d{5,}/,                     // Too many digits in a row
    /[^a-zA-Z0-9._]/,             // Invalid special characters
  ];

  const isLengthValid = username.length >= 3 && username.length <= 20;
  const isCleanPattern = /^[a-zA-Z0-9._]+$/.test(username);
  const isNotSpam = !bannedPatterns.some((pattern) => pattern.test(username));

  return isLengthValid && isCleanPattern && isNotSpam;
};


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

  const isStrong =
    isLengthValid && hasUpper && hasLower && hasDigit 

  const notCommon = !bannedPasswords.includes(password.toLowerCase());

  return isStrong && notCommon;
};
