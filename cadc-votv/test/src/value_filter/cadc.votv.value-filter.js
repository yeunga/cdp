// Create a DOM to pass in.
var targetNode = document.createElement("div");
targetNode.setAttribute("id", "myGrid");
document.body.appendChild(targetNode);

// Create the options for the Grid.
var options = {
  editable: false,
  enableAddRow: false,
  showHeaderRow: true,
  enableCellNavigation: true,
  asyncEditorLoading: true,
  forceFitColumns: true,
  explicitInitialization: true,
  topPanelHeight: 45,
  headerRowHeight: 45,
  showTopPanel: false,
  sortColumn: "Job ID",
  sortDir: "asc",
  columnOptions: {
    "User": {
      cssClass: "user_column"
    },
    "Started on": {
      cssClass: "started_on_column"
    }
  }
};

test("Numeric filter 30000 times.", 0, function ()
{
  var viewer = new cadc.vot.Viewer("#myGrid", options);

  var start = new Date();
  var mockUserFilterValue = "< 3";
  for (var i = 0; i < 30000; i++)
  {
    viewer.valueFilters(mockUserFilterValue,
                        Math.floor((Math.random() * 10) + 1));
  }

  var end = new Date();

  console.log("Took " + (end.getTime() - start.getTime()) / 1000 + " seconds.");
});

test("String substring filter.", 7, function ()
{
  var viewer = new cadc.vot.Viewer("#myGrid", options);

  var testVal = "N";
  equal(viewer.valueFilters(testVal, "null"), false, "Should not filter");
  equal(viewer.valueFilters(testVal, "Neverland"), false, "Should not filter");
  equal(viewer.valueFilters(testVal, "pull"), true, "Should filter");
  equal(viewer.valueFilters(testVal, -45), true, "Should filter");
  equal(viewer.valueFilters(testVal, 9), true, "Should filter");
  equal(viewer.valueFilters(testVal, "Pension"), false, "Should not filter");
  equal(viewer.valueFilters(testVal, "abseNce"), false, "Should not filter");
});

test("String exact match filter.", 7, function ()
{
  var viewer = new cadc.vot.Viewer("#myGrid", options);

  var testVal = "pull";
  equal(viewer.valueFilters(testVal, "null"), true, "Should filter");
  equal(viewer.valueFilters(testVal, "Neverland"), true, "Should filter");
  equal(viewer.valueFilters(testVal, "pull"), false, "Should not filter");
  equal(viewer.valueFilters(testVal, -45), true, "Should filter");
  equal(viewer.valueFilters(testVal, 9), true, "Should filter");
  equal(viewer.valueFilters(testVal, "Pension"), true, "Should filter");
  equal(viewer.valueFilters(testVal, "abseNce"), true, "Should filter");
});
