# Smart Downloads Organizer

A Python script that automatically organizes messy download folders by sorting files into categories based on their extension. It creates category folders, moves files, and generates both JSON and text reports with statistics.

## Installation & Usage

Requires Python 3. No additional packages needed — uses only built-in libraries.

Run it from the command line:

```
python3 organizer.py [directory_path]
```

If no directory is specified, it defaults to a folder called `downloads`.

Example:

```
python3 organizer.py test_downloads
```

## Features

- Categorizes files into 7 types: documents, images, archives, executables, videos, audio, and other
- Handles unusual file naming situations that could break the script, including:
  - Uppercase extensions: a file named FILE.PDF is recognized as a document just like file.pdf
  - No extension: a file named README with no dot has no extension to read, so it goes to the "other" category instead of crashing
  - Multiple dots: a file named archive.tar.gz has two dots, and the script correctly grabs only the last part (gz) as the extension
  - Hidden files: files starting with a dot like .gitignore are recognized as hidden system files, not treated as if the whole name is an extension
- Creates category folders automatically if they don't exist
- Moves files safely using shutil with error handling — won't crash if something goes wrong
- Generates a JSON report with timestamp and category counts
- Generates a human-readable text report with percentages
- Accepts any directory path as a command-line argument

## Design Decisions

**Why pathlib instead of os?**
Both pathlib and os can work with files and folders. The os module is older and treats file paths as plain text. Pathlib is a newer approach and has built-in shortcuts — for example, `path.suffix` gives you a file's extension in one step instead of having to split the filename apart yourself. The course lesson notes recommended pathlib so this is what I used.

**How are existing files handled?**
If a file can't be moved (for example, a file with the same name already exists in the destination folder), the script logs an error message and continues processing the remaining files instead of crashing. Unlike working in Finder where you get a popup asking to keep both or overwrite, a Python script running in Terminal has no popup windows — it just runs. So the try/except block catches the error and prints a message instead of stopping everything. Logging the error and moving on is what this assignment expects.

**How are statistics tracked?**
A dictionary is set up at the start with every category set to zero. Each time a file is successfully moved, the count for that category goes up by one. This dictionary is then passed to both report functions. It works just like a pivot table — counting how many items fall into each group and then summarizing the totals.

## AI Tool Usage

**What tools did I use?**
I used Claude (Anthropic) throughout this project.

**What did I use AI for?**
- Understanding the lesson concepts — I had Claude explain each section of the web app in plain language before coding
- Walking through the code step by step — Claude explained each function individually and waited for me to confirm understanding before moving on
- Comparing approaches — I had Claude compare its code against the lesson's example code, which caught unnecessary duplication
- Writing the README — Claude drafted sections and I revised them in my own words

**What did I learn from using AI?**
- Being specific in prompts gets better results. Vague prompts lead to extra back-and-forth.
- AI can write redundant code. I caught Claude duplicating logic that another function already handled, which led me to request cleaner code going forward.
- I still need to understand every line. If I can't explain what the code does, I don't use it.

## Challenges & Solutions

**Writing code independently**
I did not write this code myself. I had Claude write each function and then walked through every line to make sure I understood what it does and why. I don't feel capable of writing Python code from scratch yet, but I can read and explain what each part of this script does. Building that understanding is where I am in my learning.

**Understanding the lesson concepts before coding**
The web app covered a lot of new material — pathlib, shutil, JSON, and extension handling. I worked through each section with AI to break down what each piece does in plain language before accepting the code presented.

**The web app simulator didn't run Python**
The challenge editors in the web app expected JavaScript syntax, so my Python code kept throwing errors. I moved past the simulator exercises and focused on understanding the logic, then tested real Python on my Mac instead.

**Remembering syntax**
There's a lot of syntax to keep track of — Path objects, string slicing, f-strings, json.dump. I learned that professional developers don't memorize all of this. With AI's ability to write code correctly and quickly, the real skill is knowing what you want the program to do, communicating that clearly through prompts, and evaluating whether the result actually solves the problem. I know there is debate about this approach — some feel that if you can't write code from scratch, you can't do this work. I disagree. A calculator doesn't do the thinking for you — it frees you from getting stuck on arithmetic so you can focus on the bigger problem. AI coding tools work the same way. The value is in understanding the problem, knowing what to ask for, and being able to evaluate and explain the solution.
