<div id="form-title-history" class="ui-widget-header ui-corner-top ui-state-default" style="margin-top:0.5%;">
	<?=__("History")?>
</div>
<div id="form-history" class="ui-widget-content ui-corner-bottom">
	<table id="history-list"></table>
	<div id="history-list-pager"></div>
</div>

<script type="text/javascript">


$(function(){
	
	var historyGrid = null;
	function buildHistoryGrid(){
		historyGrid = $("#history-list").jqGrid({
			url: "<?=_url('historyData', 'Delivery', 'taoDelivery')?>", 
			datatype: "json", 
			colNames:[ __('Subject'), __('Time'), __('Actions')], 
			colModel:[ 
				{name:'subject',index:'subject'}, 
				{name:'time',index:'time'}, 
				{name:'actions',index:'actions', align:"center", sortable: false}
			], 
			rowNum:20, 
			height:300, 
			width:'',
			pager: '#history-list-pager', 
			sortname: 'subject', 
			viewrecords: false, 
			sortorder: "asc", 
			caption: __("Execution History"),
			postData: {'uri': "<?=get_data('uri')?>", 'classUri': "<?=get_data('classUri')?>"},
			gridComplete: function(){
				$.each(historyGrid.getDataIDs(), function(index, elt){
					historyGrid.setRowData(elt, {
						actions: "<a id='history_deletor_"+elt+"' href='#' class='user_deletor nd' ><img class='icon' src='<?=BASE_WWW?>img/delete.png' alt='<?=__('Delete History')?>' /><?=__('Delete')?></a>"
					});
				});
				$(".user_deletor").click(function(e){
					e.preventDefault();
					removeHistory(this.id.replace('history_deletor_', ''));
				});
			}
		});
		historyGrid.navGrid('#history-list-pager',{edit:false, add:false, del:false});
	}
	
	buildHistoryGrid();	
	
	var removeHistory = function(uri){
		if(confirm("<?=__('Please confirm history deletion')?>")){ 
			$.ajax({
				url: "<?=_url('deleteHistory', 'Delivery', 'taoDelivery')?>",
				type: "POST",
				data: {
					'historyUri': uri,
					'uri': "<?=get_data('uri')?>",
					'classUri': "<?=get_data('classUri')?>"
				},
				dataType: 'json',
				success: function(r){
					if (r.deleted){
						historyGrid.trigger("reloadGrid");
						createInfoMessage(r.message);
					}else{
						createErrorMessage(r.message);
					}
				}
			});
		}
	}
});
</script>