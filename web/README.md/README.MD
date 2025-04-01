# AI Framework Generator

A tool designed for prompt engineers to focus on business logic without getting bogged down in code details.

## Overview

The AI Framework Generator provides a structured interface for defining application components through natural language prompts. By leveraging AI, it creates code snippets for various aspects of your application, from data models to user interfaces.

## Features

### Model Registry
- Define data tables and their relationships
- Specify columns with data types and constraints
- Visualize data structures and relationships
- Export schemas to different database formats

### Functionalities
- Create business logic through natural language descriptions
- Generate service layers and utility functions
- Support for common patterns like CRUD operations
- Input validation and error handling generation

### API Handlers
- Define RESTful API endpoints through descriptions
- Generate handler code for various frameworks
- Built-in mock data for testing
- Support for authentication and authorization patterns

### UI Crafting
- Create UI components through descriptions
- Generate frontend code for popular frameworks
- Responsive design patterns
- Form handling and validation

### Interactivity
- Define user interactions and client-side behavior
- Event handling code generation
- Data fetching and state management
- Validation and user feedback patterns

### Preview
- Live preview of the generated application
- Sandbox environment for testing
- Interactive component demonstration
- Mobile and desktop view testing

### API Testing
- Test generated API endpoints
- Simulate requests and view responses
- Validate request/response patterns
- Debug API integration issues

## Getting Started

### Installation

```bash
git clone https://github.com/your-org/ai-framework-generator.git
cd ai-framework-generator
npm install
npm start
```

### Basic Usage

1. Define your data models in the **Model Registry**
2. Describe core business logic in the **Functionalities** tab
3. Define API endpoints in the **API Handlers** tab
4. Create UI components in the **UI Crafting** tab
5. Define interactions in the **Interactivity** tab
6. Preview your application in the **Preview** tab
7. Test your API in the **API Test** tab

## Example

Here's a simple example of defining a product management system:

1. **Model Registry**:
   - Create `Products` table with: id (integer), name (string), price (integer), inStock (boolean)

2. **Functionalities**:
   - "Create functions to get all products, get product by ID, and filter products by availability"

3. **API Handlers**:
   - "Create RESTful API endpoints for products with GET and POST methods"

4. **UI Crafting**:
   - "Create a product list view with a table showing products and their details"

5. **Interactivity**:
   - "Load products when the page loads and show details when a product is clicked"

## Benefits

- **Focus on Business Logic**: Spend time defining what your application does, not how it's coded
- **Rapid Prototyping**: Quickly generate working code from descriptions
- **Consistent Patterns**: Ensure consistency across your application
- **Language Agnostic**: Generate code in multiple programming languages
- **Framework Flexible**: Support for various frontend and backend frameworks

## Technical Details

- Built with HTML, CSS, JavaScript
- Uses Alpine.js for reactivity
- Bootstrap for UI components
- Axios for HTTP requests
- Modular architecture with separate HTML snippets for each section

## License

MIT License

## Contributors

- Your Name
- AI Assistant
- Community Contributors