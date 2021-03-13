# Spaced Repetition App
## Description
Spaced Repetition is an app that allows users to learn the Spanish language using a technique called "spaced repetition". The intent is to help users learn Spanish words by revealing newer and difficult words more frequently and older and easier words less frequently.
## Link to Live App & Repos
- Live App:
  - https://spaced-repetition-client-nikki-ai.vercel.app/register
- Server Repo:
  - https://github.com/nikki-ai/spaced-repetition-server
- Client Repo:
  - https://github.com/nikki-ai/spaced-repetition-client

## Application Features
- User can register using their name, a username, and a password. The password must be 8 characters long, must contain one upper case, lower case, number, and special character.
- As a returning user, the user may login using their username and password.
- Once logged in, the user will view their dashboard that provides the following information: Language, a list of words to practice, the total amount of correct and incorrect times the user has answered for a specified word, and their total amount of correct answers.
- When beginning their practice, the user will be prompted to a screen that displays a word to be translated, their total score, and their total tally for correct and incorrect answers for the given word. After answering, the user will be prompted to a results page that will inform them whether or not their answer was correct.

## Tech Stacks Used
- Front-end technologies
  - Javascript frameworks
  - CSS grid
  - React
  - Deployed via Vercel
- Back-end technologies
  - Node.js
  - RESTful Api
  - Deployed via Heroku
- Data Persistence
  - PostgreSQL
## Setup
To setup the application
1. Fork and clone the project to your machine
2. `npm install`. This will also install the application _Cypress.io_ for running browser integration tests
The project expects you have the Spaced repetition API project setup and running on http://localhost:8000.
Find instructions to setup the API here https://github.com/Thinkful-Ed/spaced-repetition-api.
## Running project
This is a `create-react-app` project so `npm start` will start the project in development mode with hot reloading by default.
## Running the tests
This project uses [Cypress IO](https://docs.cypress.io) for integration testing using the Chrome browser.
Cypress has the following expectations:
- You have cypress installed (this is a devDependency of the project)
- You have your application running at http://localhost:3000.
  - You can change the address of this expectation in the `./cypress.json` file.
- Your `./src/config.js` is using http://localhost:8000/api as the `API_ENDPOINT`
To start the tests run the command:
```bash
npm run cypress:open
```
On the first run of this command, the cypress application will verify its install. Any other runs after this, the verification will be skipped.
The command will open up the Cypress application which reads tests from the `./cypress/integration/` directory. You can then run individual tests by clicking on the file names or run all tests by clicking the "run all tests" button in the cypress GUI.
Tests will assert against your running localhost client application.
You can also start all of the tests in the command line only (not using the GUI) by running the command:
```bash
npm run cypress:run
```
This will save video recordings of the test runs in the directory `./cypress/videos/`.