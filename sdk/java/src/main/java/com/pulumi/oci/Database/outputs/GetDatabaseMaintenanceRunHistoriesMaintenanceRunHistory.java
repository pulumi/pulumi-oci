// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.outputs.GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryDbServersHistoryDetail;
import com.pulumi.oci.Database.outputs.GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistory;
import com.pulumi.oci.Database.outputs.GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryMaintenanceRunDetail;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistory {
    /**
     * @return The OCID of the current execution window.
     * 
     */
    private String currentExecutionWindow;
    /**
     * @return List of database server history details.
     * 
     */
    private List<GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryDbServersHistoryDetail> dbServersHistoryDetails;
    /**
     * @return The list of granular maintenance history details.
     * 
     */
    private List<GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistory> granularMaintenanceHistories;
    /**
     * @return The OCID of the maintenance run.
     * 
     */
    private String id;
    /**
     * @return Details of a maintenance run.
     * 
     */
    private List<GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryMaintenanceRunDetail> maintenanceRunDetails;

    private GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistory() {}
    /**
     * @return The OCID of the current execution window.
     * 
     */
    public String currentExecutionWindow() {
        return this.currentExecutionWindow;
    }
    /**
     * @return List of database server history details.
     * 
     */
    public List<GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryDbServersHistoryDetail> dbServersHistoryDetails() {
        return this.dbServersHistoryDetails;
    }
    /**
     * @return The list of granular maintenance history details.
     * 
     */
    public List<GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistory> granularMaintenanceHistories() {
        return this.granularMaintenanceHistories;
    }
    /**
     * @return The OCID of the maintenance run.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Details of a maintenance run.
     * 
     */
    public List<GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryMaintenanceRunDetail> maintenanceRunDetails() {
        return this.maintenanceRunDetails;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistory defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String currentExecutionWindow;
        private List<GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryDbServersHistoryDetail> dbServersHistoryDetails;
        private List<GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistory> granularMaintenanceHistories;
        private String id;
        private List<GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryMaintenanceRunDetail> maintenanceRunDetails;
        public Builder() {}
        public Builder(GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistory defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.currentExecutionWindow = defaults.currentExecutionWindow;
    	      this.dbServersHistoryDetails = defaults.dbServersHistoryDetails;
    	      this.granularMaintenanceHistories = defaults.granularMaintenanceHistories;
    	      this.id = defaults.id;
    	      this.maintenanceRunDetails = defaults.maintenanceRunDetails;
        }

        @CustomType.Setter
        public Builder currentExecutionWindow(String currentExecutionWindow) {
            if (currentExecutionWindow == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistory", "currentExecutionWindow");
            }
            this.currentExecutionWindow = currentExecutionWindow;
            return this;
        }
        @CustomType.Setter
        public Builder dbServersHistoryDetails(List<GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryDbServersHistoryDetail> dbServersHistoryDetails) {
            if (dbServersHistoryDetails == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistory", "dbServersHistoryDetails");
            }
            this.dbServersHistoryDetails = dbServersHistoryDetails;
            return this;
        }
        public Builder dbServersHistoryDetails(GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryDbServersHistoryDetail... dbServersHistoryDetails) {
            return dbServersHistoryDetails(List.of(dbServersHistoryDetails));
        }
        @CustomType.Setter
        public Builder granularMaintenanceHistories(List<GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistory> granularMaintenanceHistories) {
            if (granularMaintenanceHistories == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistory", "granularMaintenanceHistories");
            }
            this.granularMaintenanceHistories = granularMaintenanceHistories;
            return this;
        }
        public Builder granularMaintenanceHistories(GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistory... granularMaintenanceHistories) {
            return granularMaintenanceHistories(List.of(granularMaintenanceHistories));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistory", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder maintenanceRunDetails(List<GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryMaintenanceRunDetail> maintenanceRunDetails) {
            if (maintenanceRunDetails == null) {
              throw new MissingRequiredPropertyException("GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistory", "maintenanceRunDetails");
            }
            this.maintenanceRunDetails = maintenanceRunDetails;
            return this;
        }
        public Builder maintenanceRunDetails(GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryMaintenanceRunDetail... maintenanceRunDetails) {
            return maintenanceRunDetails(List.of(maintenanceRunDetails));
        }
        public GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistory build() {
            final var _resultValue = new GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistory();
            _resultValue.currentExecutionWindow = currentExecutionWindow;
            _resultValue.dbServersHistoryDetails = dbServersHistoryDetails;
            _resultValue.granularMaintenanceHistories = granularMaintenanceHistories;
            _resultValue.id = id;
            _resultValue.maintenanceRunDetails = maintenanceRunDetails;
            return _resultValue;
        }
    }
}
