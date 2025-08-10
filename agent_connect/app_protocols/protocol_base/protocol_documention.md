# Requirements

Design an API protocol to retrieve educational background information for a single user. This protocol should:
- Allow fetching educational background details for a specified user based on `user_id`.
- The educational background must include the institution name, major, degree, achievements, start and end dates.
- Support error handling and parameter validation.
- Implement pagination for retrieved data.

# Protocol Flow

## Interaction Flow

1. **Request**: The client sends a request to the server containing `user_id` and an optional parameter `include_details` to specify whether detailed information is required.
2. **Validation**: The server validates the input parameters.
3. **Fetch Data**: Upon successful validation, the server retrieves the educational experience data.
4. **Response**: The server sends back a response containing the educational details or an error message if applicable.

# Data Format

## Request Message Format

The request message is in JSON format with the following structure:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "messageType": {
      "type": "string",
      "const": "getUserEducation"
    },
    "messageId": {
      "type": "string",
      "format": "uuid"
    },
    "userId": {
      "type": "string"
    },
    "includeDetails": {
      "type": "boolean",
      "default": false
    },
    "page": {
      "type": "integer",
      "minimum": 1,
      "default": 1
    },
    "pageSize": {
      "type": "integer",
      "minimum": 1,
      "default": 10
    }
  },
  "required": ["messageType", "messageId", "userId"],
  "additionalProperties": false
}
```

## Response Message Format

The response message is also in JSON format and uses the following structure:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "messageType": {
      "type": "string",
      "const": "getUserEducation"
    },
    "messageId": {
      "type": "string",
      "format": "uuid"
    },
    "code": {
      "type": "integer"
    },
    "data": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "institution": {
            "type": "string"
          },
          "major": {
            "type": "string"
          },
          "degree": {
            "type": "string",
            "enum": ["Bachelor", "Master", "Doctorate"]
          },
          "achievements": {
            "type": "string"
          },
          "startDate": {
            "type": "string",
            "format": "date"
          },
          "endDate": {
            "type": "string",
            "format": "date"
          }
        },
        "required": ["institution", "major", "degree", "startDate", "endDate"]
      }
    },
    "pagination": {
      "type": "object",
      "properties": {
        "currentPage": {
          "type": "integer"
        },
        "totalPages": {
          "type": "integer"
        },
        "totalItems": {
          "type": "integer"
        }
      }
    },
    "error": {
      "type": "object",
      "properties": {
        "message": {
          "type": "string"
        },
        "details": {
          "type": "string"
        }
      },
      "required": ["message"]
    }
  },
  "required": ["messageType", "messageId", "code"],
  "additionalProperties": false
}
```

# Error Handling

The API will use standard HTTP status codes for error handling:

- **200 OK**: Request was successful and data is returned.
- **400 Bad Request**: The request parameters were invalid. The `error` field will contain details.
- **404 Not Found**: No educational data found for the given `user_id`.
- **500 Internal Server Error**: An unexpected server error occurred.

Example error response:

```json
{
  "messageType": "getUserEducation",
  "messageId": "123e4567-e89b-12d3-a456-426614174000",
  "code": 400,
  "error": {
    "message": "Invalid user_id format",
    "details": "The user_id must be a valid UUID."
  }
}
```