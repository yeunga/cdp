/**
 * Added for Story 1647.
 *
 * @type {string}
 */

var xmlData =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    + "<VOTABLE xmlns=\"http://www.ivoa.net/xml/VOTable/v1.2\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" version=\"1.2\">\n"
    + "  <RESOURCE>\n"
    + "    <TABLE>\n"
    + "      <DESCRIPTION>TEST VOTABLE</DESCRIPTION>\n"
    + "      <FIELD id=\"jobid\" name=\"Job ID\" datatype=\"char\" arraysize=\"*\" />\n"
    + "      <FIELD id=\"project\" name=\"Project\" datatype=\"char\" arraysize=\"*\" />\n"
    + "      <FIELD id=\"user\" name=\"User\" datatype=\"char\" arraysize=\"*\" />\n"
    + "      <FIELD id=\"started\" name=\"Started\" datatype=\"char\" arraysize=\"*\" />\n"
    + "      <FIELD id=\"status\" name=\"Status\" datatype=\"char\" arraysize=\"*\" />\n"
    + "      <FIELD id=\"command\" name=\"Command\" datatype=\"char\" arraysize=\"*\" />\n"
    + "      <FIELD id=\"vm_type\" name=\"VM Type\" datatype=\"char\" arraysize=\"*\" />\n"
    + "      <FIELD id=\"cpu_count\" name=\"CPUs\" datatype=\"int\" />\n"
    + "      <FIELD id=\"memory_in_mb\" name=\"Memory\" datatype=\"long\" />\n"
    + "      <FIELD id=\"job_start_count\" name=\"Job Starts\" datatype=\"int\" />\n"
    + "      <FIELD id=\"ra\" name=\"RA\" datatype=\"double\" />\n"
    + "      <FIELD id=\"dec\" name=\"Dec\" datatype=\"double\" />\n"
    + "      <FIELD id=\"calibration_level_code\" name=\"Calibration Level\" datatype=\"int\" />\n"
    + "      <DATA>\n"
    + "        <TABLEDATA>\n"
    + "          <TR>\n"
    + "            <TD>735.0</TD>\n"
    + "            <TD>2011.03.66.8.S</TD>\n"
    + "            <TD>m</TD>\n"
    + "            <TD />\n"
    + "            <TD>Idle</TD>\n"
    + "            <TD>ls</TD>\n"
    + "            <TD></TD>\n"
    + "            <TD>1</TD>\n"
    + "            <TD>3072</TD>\n"
    + "            <TD>0</TD>\n"
    + "            <TD>350.8923046994408</TD>\n"
    + "            <TD>33.496328250076225</TD>\n"
    + "            <TD>-1</TD>\n"
    + "          </TR>\n"
    + "          <TR>\n"
    + "            <TD>734.0</TD>\n"
    + "            <TD>2011.03.66.9.S</TD>\n"
    + "            <TD>hello</TD>\n"
    + "            <TD />\n"
    + "            <TD>Idle</TD>\n"
    + "            <TD>sle</TD>\n"
    + "            <TD></TD>\n"
    + "            <TD>1</TD>\n"
    + "            <TD>3072</TD>\n"
    + "            <TD>0</TD>\n"
    + "            <TD>41.63295047803702</TD>\n"
    + "            <TD>-56.008253196459115</TD>\n"
    + "            <TD>0</TD>\n"
    + "          </TR>\n"
    + "          <TR>\n"
    + "            <TD>733.0</TD>\n"
    + "            <TD>2011.03.66.10.N</TD>\n"
    + "            <TD>there</TD>\n"
    + "            <TD />\n"
    + "            <TD>Idle</TD>\n"
    + "            <TD>s</TD>\n"
    + "            <TD>BLASTabell31122006-12-21</TD>\n"
    + "            <TD>1</TD>\n"
    + "            <TD>3072</TD>\n"
    + "            <TD>0</TD>\n"
    + "            <TD>41.63295047803702</TD>\n"
    + "            <TD></TD>\n"
    + "            <TD>3</TD>\n"
    + "          </TR>\n"
    + "          <TR>\n"
    + "            <TD>623.0</TD>\n"
    + "            <TD>2011.03.66.10.N</TD>\n"
    + "            <TD>there</TD>\n"
    + "            <TD />\n"
    + "            <TD>Idle</TD>\n"
    + "            <TD>s</TD>\n"
    + "            <TD>BLASTgoods-s2006-12-21</TD>\n"
    + "            <TD>1</TD>\n"
    + "            <TD>3072</TD>\n"
    + "            <TD>0</TD>\n"
    + "            <TD></TD>\n"
    + "            <TD>-45.4232993571047</TD>\n"
    + "            <TD></TD>\n"
    + "          </TR>\n"
    + "          <TR>\n"
    + "            <TD>1111.0</TD>\n"
    + "            <TD>2011.03.66.10.N</TD>\n"
    + "            <TD>there</TD>\n"
    + "            <TD />\n"
    + "            <TD>Idle</TD>\n"
    + "            <TD>s</TD>\n"
    + "            <TD>abell3112</TD>\n"
    + "            <TD>1</TD>\n"
    + "            <TD>3072</TD>\n"
    + "            <TD></TD>\n"
    + "            <TD>189.08577100000196</TD>\n"
    + "            <TD></TD>\n"
    + "            <TD>0</TD>\n"
    + "          </TR>\n"
    + "          <TR>\n"
    + "            <TD>15.0</TD>\n"
    + "            <TD>2011.03.66.10.N</TD>\n"
    + "            <TD>there</TD>\n"
    + "            <TD />\n"
    + "            <TD>Idle</TD>\n"
    + "            <TD>s</TD>\n"
    + "            <TD>goods-s</TD>\n"
    + "            <TD>1</TD>\n"
    + "            <TD>3072</TD>\n"
    + "            <TD></TD>\n"
    + "            <TD>76.76871277764876</TD>\n"
    + "            <TD>-45.4232993571047</TD>\n"
    + "            <TD>0</TD>\n"
    + "          </TR>\n"
    + "          <TR>\n"
    + "            <TD>9854.0</TD>\n"
    + "            <TD>2011.03.66.10.N</TD>\n"
    + "            <TD>there</TD>\n"
    + "            <TD />\n"
    + "            <TD>Idle</TD>\n"
    + "            <TD>s</TD>\n"
    + "            <TD>goods-s</TD>\n"
    + "            <TD>1</TD>\n"
    + "            <TD>3072</TD>\n"
    + "            <TD></TD>\n"
    + "            <TD>0.0</TD>\n"
    + "            <TD>0.0</TD>\n"
    + "            <TD>0</TD>\n"
    + "          </TR>\n"
    + "        </TABLEDATA>\n"
    + "      </DATA>\n"
    + "    </TABLE>\n"
    + "  </RESOURCE>\n"
    + "</VOTABLE>";

// Create a DOM to pass in.
var xmlDOM = new DOMParser().parseFromString(xmlData, "text/xml");

var targetNode = document.createElement("div");
targetNode.setAttribute("id", "myGrid");
$(document.body).append($(targetNode));

// Create the options for the Grid.
var options = {
  editable: false,
  enableAddRow: false,
  showHeaderRow: true,
  enableCellNavigation: true,
  asyncEditorLoading: true,
  forceFitColumns: true,
  explicitInitialization: true,
  targetNodeSelection: "#myGrid",
  topPanelHeight: 45,
  headerRowHeight: 45,
  showTopPanel: false,
  sortColumn: "Job ID",
  sortDir: "asc",
  columnManager: {
    filterable: true
  },
  columnOptions: {
    "User": {
      cssClass: "user_column"
    },
    "Started": {
      cssClass: "started_on_column"
    }
  }
};

test("Suggest items for 73.", 1, function ()
{
  var viewer = new cadc.vot.Viewer("#myGrid", options);
  var callCount = 0;

  viewer.subscribe(cadc.vot.events.onDataLoaded, function (e, args)
  {
    viewer.render();
  });

  viewer.subscribe(cadc.vot.events.onRowsChanged, function (e, args)
  {
    console.log("Hit " + callCount + " is " + args.current);

    if (callCount++ === 1)
    {
      equal(args.current, 3, "Should be three items.");
    }
  });

  viewer.build({
                 xmlDOM: xmlDOM
               },
               function ()
               {
                 var $grid = $("#myGrid");
                 var $inputFilter = $grid.find("input#jobid_filter");
                 $inputFilter.val("73").change();
               },
               function ()
               {
                 throw new Error("Can't create viewer.");
               });
});
