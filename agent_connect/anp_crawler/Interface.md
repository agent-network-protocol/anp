
# ad.json Interface的处理

## 从ad.json中获取Interface,并转换为OpenAI tools

使用ANPInterfaceConverter将ad.json中的Interface转换为OpenAI tools。
同时，为每个tool，生成一个对应的ANPInterface，ANPInterface中记录转换后的tools，还要记录openrpc中，除methods之外的信息。

ANPInterface有一个接口，可以根据OpenAI api 调用tools的信息，使用servers中的端点，通过https post发送json rpc请求。其中http相关的请求发送，使用anp_client.py中的方法，这里实现了didwba的认证。

下面是一个符合OpenRPC规范的接口描述文档示例：

```json
{
  "openrpc": "1.3.2",
  "info": {
    "title": "Grand Hotel Services API",
    "version": "1.0.0",
    "description": "JSON-RPC 2.0 API for hotel services including room management, booking, and guest services",
    "x-anp-protocol-type": "ANP",
    "x-anp-protocol-version": "1.0.0"
  },
  "security": [
    {
      "didwba": []
    }
  ],
  "servers": [
    {
      "name": "Production Server",
      "url": "https://grand-hotel.com/api/v1/jsonrpc",
      "description": "Production server for Grand Hotel API"
    }
  ],
  "methods": [
    {
      "name": "searchRooms",
      "summary": "Search available hotel rooms",
      "description": "Search available hotel rooms based on criteria such as dates, number of guests, and room type",
      "params": [
        {
          "name": "searchCriteria",
          "description": "Room search criteria",
          "required": true,
          "schema": {
            "type": "object",
            "properties": {
              "checkIn": {
                "type": "string",
                "format": "date",
                "description": "Check-in date in YYYY-MM-DD format"
              },
              "checkOut": {
                "type": "string", 
                "format": "date",
                "description": "Check-out date in YYYY-MM-DD format"
              },
              "guests": {
                "type": "integer",
                "minimum": 1,
                "maximum": 8,
                "description": "Number of guests"
              },
              "roomType": {
                "type": "string",
                "enum": ["standard", "deluxe", "suite", "presidential"],
                "description": "Preferred room type"
              }
            },
            "required": ["checkIn", "checkOut", "guests"]
          }
        }
      ],
      "result": {
        "name": "searchResult",
        "description": "Search results containing available rooms",
        "schema": {
          "type": "object",
          "properties": {
            "rooms": {
              "type": "array",
              "items": {
                "$ref": "#/components/schemas/Room"
              }
            },
            "total": {
              "type": "integer",
              "description": "Total number of available rooms"
            }
          }
        }
      }
    }
  ]
}
```

## 从OpenAI tools的调用，到找到anp_interface，并且触发http请求的发送，然后返回http调用结果

对于ANPInterfaceConverter返回的tools和ANPInterface，需要根据tools的方法名或者函数名，关联进行保存。后面OpenAI tools调用的时候，能够根据方法名或者函数名，找到对应的ANPInterface，然后调用ANPInterface的接口，发送http请求。









