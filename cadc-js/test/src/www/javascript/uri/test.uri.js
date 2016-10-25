test("Test URI components from full URL.", 1, function()
{
  var myURI = new cadc.web.util.URI("http://www.mysite.com/path/1/2/item.txt");

  equal(myURI.getPath(), "/path/1/2/item.txt",
        "Output should be /path/1/2/item.txt");
});

test("Test URI components from full URL 2.", 6, function()
{
  var myURI = new cadc.web.util.URI("http://www.mysite.com/path/item.txt?a=b&c=d");

  equal(myURI.getPath(), "/path/item.txt",
        "Path should be /path/item.txt");

  var q = myURI.getQuery();

  equal("b", q.a[0], "Query string param a is wrong.");
  equal("d", q.c[0], "Query string param c is wrong.");

  // the path should remain unchanged
  var path = myURI.getPath();
  myURI.clearQuery();
  equal(path, "/path/item.txt",
        "clearQuery: Path should be /path/item.txt");
  // the relative path should be cleaned up
  equal(path, myURI.getRelativeURI(),
        "clearQuery: RelativeURI should be same as Path after clearQuery");

  q = myURI.getQuery();
  var unused;
  try
  {
    unused = q.a[0];
  }
  catch(e)
  {
    equal(undefined, unused, "clearQuery: didn't get unused");
  }
});

test("Test empty query.", 1, function()
{
  var myURI = new cadc.web.util.URI("http://www.mysite.com/path/");

  var q = myURI.getQuery();

  equal("{}", JSON.stringify(q), "Query object should be empty.");
});

test("Test URI components from URI.", 1, function()
{
  var myURI = new cadc.web.util.URI("caom2:path/a/b/item.fits");

  equal(myURI.getPath(), "path/a/b/item.fits",
        "Output should be path/a/b/item.fits");
});

test("Test parse out full relative URI.", 1, function()
{
  var testSubject =
      new cadc.web.util.URI("http://www.mysite.com/path/item.txt?a=b&c=d");

  equal(testSubject.getRelativeURI(), "/path/item.txt?a=b&c=d",
        "Relative URI should be: /path/item.txt?a=b&c=d");
});

test("Test parse out path only relative URI.", 2, function()
{
  var testSubject =
      new cadc.web.util.URI("http://www.mysite.com/path/item.txt");

  equal(testSubject.getRelativeURI(), "/path/item.txt",
        "Relative URI should be: /path/item.txt");

  // Test for encoded query parameters.
  testSubject = new cadc.web.util.URI(
      "http://www.mysite.com/my/path?A=B%20C.D%20AS%20%22E%22");

  equal(testSubject.getRelativeURI(), "/my/path?A=B%20C.D%20AS%20%22E%22",
        "Relative URI should be: /my/path?A=B%20C.D%20AS%20%22E%22");
});

test("Handle multiple values for single key.", 1, function()
{
  var testSubject =
      new cadc.web.util.URI("http://www.mysite.com/path/item.txt?A=Eh&A=S");

  deepEqual(testSubject.getQueryValues("A"), ["Eh", "S"],
            "Query values for 'A' should have two items ['Eh', 'S'].");
});

test("Encoded relative URI.", 1, function()
{
  var testSubject =
      new cadc.web.util.URI("http://www.mysite.com/path/item.txt?A=Eh&A=S#/go/here");

  equal(testSubject.encodeRelativeURI(),
        "/path/item.txt?A=Eh&A=S%23%2Fgo%2Fhere",
        "Encoded relative URI is wrong.");
});

test("Set query parameters.", 2, function()
{
  var testSubject =
      new cadc.web.util.URI("http://www.mysite.com/path/item.txt?param1=val1&param2=val2&param2=val3&param3=val4");

  testSubject.setQueryValue("param1", "valX");

  equal(testSubject.getQueryValue("param1"), "valX",
        "Parameter replacement is wrong.");

  try
  {
    testSubject.setQueryValue("param2", "valY");
  }
  catch (e)
  {
    equal(e.message,
          "There are multiple parameters with the name 'param2'.",
          "Wrong error message.");
  }
});

test("Remove query parameters.", 3, function()
{
  var testSubject =
      new cadc.web.util.URI("http://www.mysite.com/path/item.txt?param1=val1&param2=val2&param2=val3&param3=val4");

  testSubject.removeQueryValues("param1");

  equal(testSubject.getQueryValue("param1"), null, "Still has param1.");

  testSubject.removeQueryValues("param2");

  equal(testSubject.getQueryValue("param2"), null, "Still has param2.");

  // Should still have param3.
  equal(testSubject.getQueryValue("param3"), "val4",
        "Should still have param3.");
});

test("Convert back to string.", 6, function()
{
  var testSubject =
      new cadc.web.util.URI("http://www.mysite.com/path/item.txt?param1=val1&param2=val2&param2=val3&param3=val4#hash=42");

  equal(testSubject.toString(),
        "http://www.mysite.com/path/item.txt?param1=val1&param2=val2&param2=val3&param3=val4#hash=42",
        "Wrong URI string.");

  testSubject.removeQueryValues("param1");

  equal(testSubject.getQueryValue("param1"), null, "Still has param1.");
  equal(testSubject.toString(),
        "http://www.mysite.com/path/item.txt?param2=val2&param2=val3&param3=val4#hash=42",
        "Wrong URI string.");

  testSubject = new cadc.web.util.URI("http://www.mysite.com:4080/aq/");

  equal(testSubject.toString(), "http://www.mysite.com:4080/aq/",
        "Wrong URI string.");

  // Query string only.
  testSubject = new cadc.web.util.URI("?param1=val1&param2=val2&param2=val3&param3=val4");

  equal(testSubject.toString(), "?param1=val1&param2=val2&param2=val3&param3=val4",
        "Wrong URI query string.");

  testSubject =
    new cadc.web.util.URI("http://www.mysite.com/path/item.txt?param1=val1&param2=val%26%202&param2=val3&param3=val%26#hash=42");
  equal(testSubject.toString(),
        "http://www.mysite.com/path/item.txt?param1=val1&param2=val%26%202&param2=val3&param3=val%26#hash=42");
});

test("Test toString with encoded query string", 1, function()
{
  var testSubject =
    new cadc.web.util.URI("http://www.mysite.com/path/item.txt?param1=val1&param2=val3#hash=42");

  testSubject.setQueryValue("param2", "val& 2");
  testSubject.setQueryValue("param3", "val&");

  equal(testSubject.toEncodedString(),
        "http://www.mysite.com/path/item.txt?param1=val1&param2=val%26%202&param3=val%26#hash=42");
});
