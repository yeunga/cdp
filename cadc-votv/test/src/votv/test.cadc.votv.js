/*
 * Created by goliaths on 06/08/15.
 */

var xmlData =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    + "<VOTABLE xmlns=\"http://www.ivoa.net/xml/VOTable/v1.2\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" version=\"1.2\">\n"
    + "  <RESOURCE>\n"
    + "    <TABLE>\n"
    + "      <FIELD name=\"Job ID\" datatype=\"char\" arraysize=\"*\" />\n"
    + "      <FIELD name=\"Project\" datatype=\"char\" arraysize=\"*\" />\n"
    + "      <DATA>\n"
    + "        <TABLEDATA>\n"
    + "          <TR>\n"
    + "            <TD>735.0</TD>\n"
    + "            <TD>2011.03.66.8.S</TD>\n"
    + "          </TR>\n"
    + "          <TR>\n"
    + "            <TD>734.0</TD>\n"
    + "            <TD>2011.03.66.9.S</TD>\n"
    + "          </TR>\n"
    + "          <TR>\n"
    + "            <TD>733.0</TD>\n"
    + "            <TD>2011.03.66.10.N</TD>\n"
    + "          </TR>\n"
    + "          <TR>\n"
    + "            <TD>733.0</TD>\n"
    + "            <TD>2011.03.66.10.N</TD>\n"
    + "          </TR>\n"
    + "        </TABLEDATA>\n"
    + "      </DATA>\n"
    + "    </TABLE>\n"
    + "  </RESOURCE>\n"
    + "</VOTABLE>";

// Create a DOM to pass in.
var xmlDOM = new DOMParser().parseFromString(xmlData, "text/xml");

function createTestDOM()
{
  var y = document.createElement("div");
  y.setAttribute("id", "myOtherGrid");

  var node = document.createElement("div");
  node.setAttribute("id", "myGrid");
  document.body.appendChild(y);
  document.body.appendChild(node);

  var $prevMyGrid = $("#myOtherGrid");
  var $node3 = $("<img src='abc.gif' alt='test image' class='grid-header-icon'/>");
  $prevMyGrid.append($node3);
  $node3 = $("<div class='grid-header-label'/>");
  $prevMyGrid.append($node3);
}

// Create the options for the Grid.
var options = {
  editable: false,
  pager:false,
  maxRowLimitWarning: "too many",
  maxRowLimit: -1
};

/**
 * Check if _str ends with the _subStr value.
 */
function endsWith(_str, _subStr)
{
  return (_str.indexOf(_subStr) === (_str.length - _subStr.length));
}


test("Results page start/end events, over-ridden and default results.", 7, function ()
{
  var sttic = function(count1, count2)
  {
    return "Showing " + count1 + " of " + count2 + " rows. ";
  };

  var msgFn = function(msg)
  {
    ok(true, "atDataLoadComplete over-ridden function called");
    return function(c1, c2, $label)
    {
      var newMessage = msg(c1, c2);
      $label.text(newMessage);
    }
  };

  // check an over-ridden implementation
  options.atDataLoadComplete = msgFn(sttic);

  createTestDOM();

  try
  {
    var viewer = new cadc.vot.Viewer("#myGrid", options);
    viewer.build({
          xmlDOM: xmlDOM
        },
        function ()
        {
          // empty
        },
        function (jqXHR, status, message)
        {
          console.log("Error while building.");
        }
    );

    // non-default implementations after event triggering

    var $myGrid = $("#myGrid");
    var $prevMyGrid = $("#myOtherGrid");

    $myGrid.trigger(cadc.vot.onDataLoadComplete);

    var $result = $myGrid.prev().css("background-color");
    equal("rgba(0, 0, 0, 0)", $result, "non-default background color checked");

    $result = $prevMyGrid.find("img").attr("src");
    ok(endsWith($result, ".png"),
       "non-default file name checked - un-changed from initial");

    $result = $prevMyGrid.find(".grid-header-label").text();
    ok(endsWith($result, "rows. "),
                "non-default row limit warning text checked");

    // default options
    options.atDataLoadComplete = undefined;
    options.atPageInfoChanged = undefined;

    viewer = new cadc.vot.Viewer("#myGrid", options);
    viewer.build({
          xmlDOM: xmlDOM
        },
        function ()
        {
          // empty
        },
        function (jqXHR, status, message)
        {
          console.log("Error while building.");
        }
    );

    $myGrid.trigger(cadc.vot.onDataLoadComplete);

    $result = $myGrid.prev().css("background-color");
    equal("rgb(235, 235, 49)", $result, "background color checked");

    $result = $prevMyGrid.find("img").attr("src");
    ok(endsWith($result, "/cadcVOTV/images/transparent-20.png"),
       "file name checked");

    $result = $prevMyGrid.find(".grid-header-label").text();
    ok(endsWith($result, options.maxRowLimitWarning),
       "row limit warning text checked");

  }
  catch (e)
  {
    console.log(e);
    console.log(e.stack);
  }
});
