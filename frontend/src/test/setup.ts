import '@testing-library/jest-dom/vitest'

// jsdom does not implement scrolling; the layout scrolls to top on navigation.
window.scrollTo = () => {}
