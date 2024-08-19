# SQL_Testing_Tool
burpsuite中的sql注入测试插件

在burpsuite插入插件后，找到Extensions —> 找到Burp extensions的name —> SQL Injection Payload Injector —> Output

当每次抓包如果插件识别到了有参数存在sql注入，就会返回注入点和注入类型，如果存在能够识别的waf还能返回waf的名称