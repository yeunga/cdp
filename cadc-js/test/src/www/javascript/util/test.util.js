test("Test String util.", 6, function ()
{
  var stringUtil = new cadc.web.util.StringUtil("MY&&<>VAL");

  var output = stringUtil.sanitize();

  equal(output, "MY&amp;&amp;&lt;&gt;VAL",
        "Output should be MY&amp;&amp;&lt;&gt;VAL");

  equal(stringUtil.hasText(), true, "Should return true.");

  stringUtil = new cadc.web.util.StringUtil("");
  equal(stringUtil.hasText(), false, "Should return false.");

  stringUtil = new cadc.web.util.StringUtil(-14.567);
  equal(stringUtil.hasText(), true, "Should return true.");

  stringUtil = new cadc.web.util.StringUtil(0);
  equal(stringUtil.hasText(), true, "Should return true.");

  stringUtil = new cadc.web.util.StringUtil("Val {0} is {1} but not {2}");
  equal(stringUtil.format("ZERO", "ONE"), "Val ZERO is ONE but not {2}",
        "String does not match.");
});

test("Test Number Format", 5, function ()
{
  var testSubject = new cadc.web.util.NumberFormat(88.0, 4);

  equal(testSubject.formatFixation(), "88.0000", "Wrong fixation.");
  equal(testSubject.formatPrecision(), "88.00", "Wrong precision.");

  /*
   * Exponent value is eleven (11).
   */
  testSubject = new cadc.web.util.NumberFormat(0.54842, 4);

  equal(testSubject.formatExponentOrFloat(), "0.5484", "Wrong %.g equivalent");

  testSubject = new cadc.web.util.NumberFormat(548428932789.25684, 4);

  equal(testSubject.formatExponentOrFloat(), "5.4843e+11",
        "Wrong %.g equivalent");

  testSubject = new cadc.web.util.NumberFormat(548428932789.25684, 12);

  equal(testSubject.formatExponentOrFloat(), "548428932789.256835937500",
        "Wrong %.g equivalent");
});

test("Array Util subtractions", 7, function ()
{
  try
  {
    new cadc.web.util.Array();
  }
  catch (e)
  {
    equal(e.message, "Base array is required.", "Wrong error message.");
  }

  var testSubject = new cadc.web.util.Array([]);

  var result1 = testSubject.subtract([]);
  deepEqual(result1, [], "Should be empty array.");

  try
  {
    testSubject.subtract(null);
  }
  catch (e)
  {
    equal(e.message, "Subtract requires an array or a filter function.",
          "Wrong error message.");
  }

  try
  {
    testSubject.subtract();
  }
  catch (e)
  {
    equal(e.message, "Subtract requires an array or a filter function.",
          "Wrong error message.");
  }

  testSubject = new cadc.web.util.Array([1, 2, 3, 4, 5, 6, 7]);
  var result3 = testSubject.subtract([3, 4]);
  deepEqual(result3, [1, 2, 5, 6, 7], "Should only be missing [3, 4]");

  testSubject = new cadc.web.util.Array([1, 2, 66, 33, null, "t", 4, 5]);
  var result4 = testSubject.subtract([3]);
  deepEqual(result4, [1, 2, 66, 33, null, "t", 4, 5],
            "Should be full array returned.");

  testSubject = new cadc.web.util.Array(
      [
        {
          id: 4,
          name: "four"
        },
        {
          id: 5,
          name: "five"
        },
        {
          id: 88,
          name: "eighty-eight"
        }
      ]);
  var result5 = testSubject.subtract(function (element)
                                     {
                                       var check = [
                                         {
                                           id: 1,
                                           name: "one"
                                         },
                                         {
                                           id: 5,
                                           name: "five"
                                         },
                                         {
                                           id: 100,
                                           name: "one-hundred"
                                         }
                                       ];

                                       for (var ci = 0; ci < check.length; ci++)
                                       {
                                         if (check[ci].id == element.id)
                                         {
                                           return false;
                                         }
                                       }

                                       return true;
                                     });
  deepEqual(result5, [
    {
      id: 4,
      name: "four"
    },
    {
      id: 88,
      name: "eighty-eight"
    }
  ], "Should only be missing [4, 88]");
});

test("Array sort.", 3, function ()
{
  var testSubject = new cadc.web.util.Array(["one", "four", "alpha", "zed", "98"]);

  var result1 = testSubject.sort();
  deepEqual(result1, ["98", "alpha", "four", "one", "zed"], "Wrong result.");

  try
  {
    testSubject.sort("BOGUS");
  }
  catch (e)
  {
    equal(e.message,
          "Property 'BOGUS' does not exist in the objects being compared.",
          "Wrong error message.");
  }

  testSubject = new cadc.web.util.Array(
      [
        {
          id: 4,
          name: "four"
        },
        {
          id: 5,
          name: "five"
        },
        {
          id: 88,
          name: "eighty-eight"
        }
      ]);

  var result2 = testSubject.sort("name");
  deepEqual(result2, [
    {
      id: 88,
      name: "eighty-eight"
    },
    {
      id: 5,
      name: "five"
    },
    {
      id: 4,
      name: "four"
    }
  ], "Wrong sorted array.");
});

test("String util matches", 3, function()
{
  var testSubject = new cadc.web.util.StringUtil(
    "ALL YOUr base Are BEELong to me!");

  equal(testSubject.matches(/long/gi), true, "Should match");
  equal(testSubject.matches(/belong/gi), false, "Should not match");
  equal(testSubject.matches(/me!/gi), true, "Should match");
});

test("String util contains", 5, function()
{
  var testSubject = new cadc.web.util.StringUtil(
    "ALL YOUr base Are BEELong to me!");

  equal(testSubject.contains("BEEL", false), true, "Should contain");
  equal(testSubject.contains("belong"), false, "Should not contain");
  equal(testSubject.contains("!"), true, "Should contain");
  equal(testSubject.contains("BAse"), true, "Should contain");
  equal(testSubject.contains("are", true), false, "Should not contain");
});