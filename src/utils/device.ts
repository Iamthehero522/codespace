// src/utils/device.ts
//
// Generates or retrieves a stable UUID v4 for this browser session.
// Stores the UUID in localStorage under the key "deviceId".

function generateUuidV4(): string {
  // Courtesy of RFC4122-compliant v4 generator:
  //   https://stackoverflow.com/a/2117523/5672715
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (crypto.getRandomValues(new Uint8Array(1))[0] & 0x0f) >> 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

export function getOrCreateDeviceId(): string {
  const STORAGE_KEY = 'deviceId';
  let existing = localStorage.getItem(STORAGE_KEY);
  if (existing) {
    return existing;
  }

  const newId = generateUuidV4();
  localStorage.setItem(STORAGE_KEY, newId);
  return newId;
}
