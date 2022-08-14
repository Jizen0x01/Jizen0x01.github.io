---
title: "Javascript Basics - THM"
date: "2022-06-30"
layout: single
---
Learn JavaScript, the high-level, multi-paradigm language of the web.

# Task 1  Intro to JavaScript

During this room, we will be covering the basics of the programming language JavaScript.

The main purpose of this language is to implement interactiveness into webpages and web applications, but thanks to the millions of individuals in the community, we've been able to control more than just the interactiveness of web pages.

Thanks to the community, we can now use JavaScript to control servers, create video games, code mobile applications, and can even be used for cybersecurity in some scenarios.

- No Answers needed.

***

# Task 2  Variables & Operators

We will not be covering much HTML in this room, but you can easily link your JavaScript file by using a Script element.

```

<body>

  <script src="script.js"></script>

</body>

```

Remember to put the script tag right before the closing body tag. This way our HTML code will execute before our external JavaScript document.

## Variables


There are 3 types of variables in JavaScript: var, let, and const.

- **let** : If a variable is going to be reassigned later within the application, this is the ideal variable type to use.

- **var**: It's better to use either let or const for variables, but this variable type will still work and is still used in applications to this day. This variable can be updated and re-declared.

- **const**: If the variable will never change or won't be reassigned anywhere else in the application, this keyword is the best option.



Good things to remember:

The **var** variable is globally scoped and can be updated and re-declared.

The **let** variable is block-scoped and can be updated but not re-declared.

The **const** variable is block-scoped and cannot be updated or re-declared.

```javascript

var variableOne = 'Linus Torvalds';                      // globaly variable. can be updated and redecleared

let variableTwo = 50;                                    // block-scoped and can be updated but not re-declared.

const variableThree = 'Creator of the Linux Kernel';     //block-scoped and cannot be updated or re-declared.

```

## Data types


![image](https://user-images.githubusercontent.com/70459751/176715523-bcbc53d1-a7f1-4bc5-ae16-92a1c8ddc213.png)


## Arithmetic Operators

![image](https://user-images.githubusercontent.com/70459751/176715665-e679ac8a-ece0-4e32-aeee-e9e780f473c8.png)


## Comparison Operators

![image](https://user-images.githubusercontent.com/70459751/176715741-490d5ba9-cecc-4ac9-95a8-1dd7d250e261.png)


## Extra data types

- Strings: 'Morpheus'

- Arrays: [1, 2, 3]

- Objects: {Name: 'John', Occupation: 'Master Hacker'}

- Booleans: true (or false)

- Numbers: 455

- Floating-Point Numbers: 10.5



### What type of data type is this: 'Neo'?
- Answer starts with **S** 

### What data type is true/false?
- Answer starts with **B** 

### What is John's occupation?
- (Return to the extra data types to find the Answer :) )

### What tag is used for linking a JavaScript file to HTML?
- What is the second part of this language name 🙂

***

# Task 3  Conditionals

Example:
```javascript

if (5 === 5) {

console.log('Hello World!'); // Prints Hello World! to the console

};

```

In plain English, if a condition is met, then the code will run. 

There are also else if statements, which look like this:

```javascript

if (5 === 10) {

console.log('Hello World!'); // Skips this code

} else if (10 === 10) {

console.log('Hello World!'); // Prints Hello World! to the console

};

```

Basically, the else keyword concludes our if conditional. 

## Switch Cases

If you need to test multiple conditions, then most of the time switch cases are best for optimization and readability within your code.

```javascript

const animal = 3;

switch (animal) {

case 1:

document.write('Cow');

break;

case 2:

document.write('Chicken');

break;

case 3:

document.write('Monkey');

break;

default:

document.write('Animal?');

} // Outputs Monkey

```

### Congratulations! You can now write conditionals!
- No Answers needed ✌️

***

# Task 4  Functions

Functions are one of the most vital parts of programming. 

This is a function in **ES6** (ECMAScript 6):

```javascript

const func = (a, b) => {

    let nums = a * b;

    console.log(nums); 

}

func(25, 10); // Outputs 250

```

**ES5** :

```javascript


function func(a, b) // Everything inside of the parenthesis defines our parameter(s)

{

    let nums = a * b;

    console.log(nums);

}

func(25, 10);  // Outputs 250

```

### Finished with Functions!
- No Answers needed

***

# Task 5  Objects & Arrays

Learning about Objects and Arrays are heavy subjects, but let's try to break them into easy to understand sections.

Let's start with Objects.

## Objects

The most important thing about objects is to remember that they're just another variation of variables.

```javascript

var choosePill = {
    pillOne: 'Red',
    pillTwo: 'Blue'
}

```

table displaying the code object.
![image](https://user-images.githubusercontent.com/70459751/176719032-828d5d2b-d36a-4deb-b7be-d93b4f7dbfe2.png)

we can also store numbers.
```javascript

var choosePill = {
    pillOne: 'Red',
    pillTwo: 'Blue',
    numberOfPills: 2
}
var choice = choosePill.pillOne; // This will access the Objects property

```

![image](https://user-images.githubusercontent.com/70459751/176719354-54f0c3a1-4318-4495-994d-3ace464a88ba.png)


## Arrays

Arrays are fairly similar to objects, they have different stored values and syntax, but can be used for almost anything.

```javascript

var choosePill = ['Red', 'Blue', 2];

var choice = choosePill[0];

console.log(choice); // Outputs 'Red'
 

```

**Reminder** : Most programming languages start from 0, not 1, so when we access the choosePill variable, we grab the value from the 1st position.

## Quick Challenge

What is the output of this code **(Question #3)** ?

```javascript

var mrRobot = ['Elliot', 'Angela', 'Tyrell', 'Darlene'];

let character = mrRobot[2];

console.log(character); // What is the output?


```


### What type of brackets are used for arrays?
- The answer is one of these => [] or {} 😁

### What color pill did we choose?
-Answer format is ( color + pill ) 😁

### What is the output of this code?
- The Answer is the third item of Array 😁

***

# Task 6  Loops


There are for loops, while loops, and do...while loops. Due to the complex nature of looping, I will be explaining the basic logic behind them


## For Loop

```javascript

for (a = 1; a <= 10; a++) {
    console.log(`Number: ${a}`); // Outputs 1-10 in our console
}

```

- The first component (a = 1): Executes before the loop starts.

- The second component (a <= 10): Defines the condition for our loop.

- The third component (a++): Executes each time after the loop starts.


## While Loop

```javascript

let x = 0;

while (x <= 3) {

console.log(x++); // Prints 0-3

}

```

This code will loop through x as long as it is less than or equal to three. 


## Do...While Loop


The basics of the do...while loop is the code will execute the loop before checking if the condition is true.
 
 ```javascript
 
let c = 10;

do {

console.log(c++); // Outputs 10-50

} while (c <= 50);

```


### Loops repeat until the written code is finished running (true/false)
- Try Answer 

### What loop doesn't require the condition to be true for it execute at least once?
- The last kind of loops 🙂

***

# Task 7  Document Object Model (DOM)

Here is what we will be covering in the DOM section
 
 ```javascript
 
document.getElementByID('Name_of_ID'); // Grabs the element with the ID name from the connected HTML file
document.getElementByClassName('Name_of_Class'); // Grabs the element with the class name from the connected HTML file
document.getElementByTagName('Name_of_Tag'); // Grabs a specific tag name from the connected HTML file
 
 ```
 
 There are also methods we can use to access different things within our HTML files such as addEventListener, removeEventListener, and many more.
 
## Most used of DOM


- onclick: Activates when a user clicks on the specific element

- onmouseover: Activates when a user hovers over a specific element

- onload: Activates when the element has loaded

[Many of DOMs are here!](https://www.w3schools.com/js/js_htmldom_events.asp)

## Code Example

![image](https://user-images.githubusercontent.com/70459751/176724152-d9d258c3-2455-419a-8c53-847aed047d2f.png)

**Now when a user clicks on the Click Me button, an alert pops up that says POP!!!**


### What is the DOM?
- Answer it Yourself ✌️

***

# Task 8  XSS

In this section, we'll be covering a few things that JavaScript can be used for in the information security industry.

## XSS

Cross-Site Scripting is a security vulnerability that's typically found in web applications which can be used to execute a malicious script on the target's machine.

There are multiple types of attack when talking about XSS, here are some of my favorites:

- Keylogging

- Stealing Cookies

- Phishing

and many more

A **keylogger** is used by setting up an event listener on the target's keyboard, which will track their keystrokes and save them on the attacker's server.

When an attacker steals a target's **cookies**, they can use that information to log in as the user without needing advanced authentication or even just find information stored in the cookies that could lead to devastating effects on the target's online saved accounts.

**Phishing** is an interesting type of exploitation, an attacker can clone the website you're logging into and steal your credentials without you ever knowing.

![image](https://user-images.githubusercontent.com/70459751/176725102-1cc87c3b-7eda-4ee5-8a36-81ed24480989.png)

The three most common types that I've seen of XSS are DOM-Based XSS (type-0 XSS), Reflected XSS (Non-Persistent XSS), and Stored XSS (Persistent XSS):

- DOM-Based XSS: This is when an attack payload is executed by manipulating the DOM (Document Object Model) in the target's browser. This type uses the client-side code instead of server-side code.

- Reflected XSS: This is when a malicious script bounces off another website onto the target's web application or website. Normally, these are passed in the URL as a query, and it's easy as making the target click a link. This type originates from the target's request.

- Stored XSS: This is when a malicious script is directly injected into the webpage or web application. This type originates from the website's database.

JavaScript is just a language, but when combined with certain techniques and tools, you can do some unbelievably devastating things to a target machine.

Here are a few interesting, more in-depth, resources used for JavaScript in Cybersecurity:

- STÖK's "Hacker101 - JavaScript for Hackers": [Hacker101](https://www.youtube.com/watch?v=FTeE3OrTNoA)

- TryHackMe's "Cross-site Scripting" Room: [TryHackMe](https://tryhackme.com/room/xss)

- Cross-Site Scripting (XSS) OWASP Website: [OWASP Website](https://owasp.org/www-community/attacks/xss/)

### What is it called when XSS is used to record keystrokes?
- Answer is the first type of xss attacks ✌️

***

# Task 9  Final Notes

Since we only touched on the very basics, here are some free resources to continue learning JavaScript:

- [Mozilla](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
- [W3Scools](https://www.w3schools.com/js/default.asp)

What wasn't covered in this room:

- Libraries or Frameworks

- ES6 Destructuring
 
- Advanced Methods
 
- And so much more!

***

# Task 10  JavaScript Challenge

For our challenge, we will be sorting an array of numbers using a JavaScript method.

## Sort the array [1,10,5,15,2,7,28,900,45,18,27]

Go to google and search about sorting an array to know the answer!

But i will help you! ❤️

Check out this link to W3Scools!

[W3Scools](https://www.w3schools.com/js/js_array_sort.asp)

- After typing the code and run it the Answer will be sorting them in Ascending order


![](https://media.giphy.com/media/fuJPZBIIqzbt1kAYVc/giphy.gif)
