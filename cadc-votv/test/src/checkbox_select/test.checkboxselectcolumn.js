test("Test formatter.", 5, function ()
{
  var testSubject = new CADC.CheckboxSelectColumn({
    cssClass: "slick-cell-checkboxsel",
    width: 55,
    headerCssClass: "slick-header-column-checkboxsel"
  });

  var output1 = testSubject.getColumnDefinition()["formatter"]();

  equal(output1, null, "Should be null output.");

  var dataView = new Slick.Data.DataView({inlineFilters: true});

  dataView.getItems().push({"id": "01", "name": "COL1", "download_id": "schema://download/01"});
  dataView.getItems().push({"id": "02", "name": "COL2", "download_id": "schema://download/02"});

  var grid = new Slick.Grid("#testGrid", dataView,
                            [{"id": "id", "name": "name"}]);

  grid.setSelectionModel(new CADC.RowSelectionModel());

  testSubject.init(grid);

  // Select the first row.
  grid.setSelectedRows([0]);

  var output2 = testSubject.getColumnDefinition()["formatter"](1, null, null, null,
                                                               grid.getData().getItems()[1]);

  equal(output2, "<input class='_select_02' type='checkbox' />",
        "Should be unchecked checkbox output for first row.");

  var output3 = testSubject.getColumnDefinition()["formatter"](0, null, null, null,
                                                               grid.getData().getItems()[0]);

  equal(output3, "<input class='_select_01' type='checkbox' checked='checked' />",
        "Should be checked checkbox output for second row.");


  // Enable one-click downloads.
  console.log("Enabling one-click downloads...");

  testSubject = new CADC.CheckboxSelectColumn({
    cssClass: "slick-cell-checkboxsel",
    width: 55,
    headerCssClass: "slick-header-column-checkboxsel",
    enableOneClickDownload: true,
    oneClickDownloadURL: "/get",
    oneClickDownloadURLColumnID: "download_id"
  });

  testSubject.init(grid);

  // Select the second row.
  grid.setSelectedRows([1]);

  var output4 = testSubject.getColumnDefinition()["formatter"](1, null, null, null,
                                                               dataView.getItems()[1]);

  equal(output4, "<input class='_select_02' type='checkbox' checked='checked' />" +
                 "<a id='_one-click_02' href='/get?ID=schema%3A%2F%2Fdownload%2F02' class='no-propagate-event'><span class='wb-icon-drive-download margin-left-small no-propagate-event'></span></a>",
        "Should be checked checkbox output and one-click download link for second row.");

  var output5 = testSubject.getColumnDefinition()["formatter"](0, null, null, null,
                                                               grid.getData().getItems()[0]);

  equal(output5, "<input class='_select_01' type='checkbox' />" +
                 "<a id='_one-click_01' href='/get?ID=schema%3A%2F%2Fdownload%2F01' class='no-propagate-event'><span class='wb-icon-drive-download margin-left-small no-propagate-event'></span></a>",
        "Should be unchecked checkbox output and one-click download link for second row.");
});
