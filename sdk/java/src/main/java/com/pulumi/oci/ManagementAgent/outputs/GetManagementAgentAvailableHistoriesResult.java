// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ManagementAgent.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ManagementAgent.outputs.GetManagementAgentAvailableHistoriesAvailabilityHistory;
import com.pulumi.oci.ManagementAgent.outputs.GetManagementAgentAvailableHistoriesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetManagementAgentAvailableHistoriesResult {
    /**
     * @return The list of availability_histories.
     * 
     */
    private List<GetManagementAgentAvailableHistoriesAvailabilityHistory> availabilityHistories;
    private @Nullable List<GetManagementAgentAvailableHistoriesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return agent identifier
     * 
     */
    private String managementAgentId;
    private @Nullable String timeAvailabilityStatusEndedGreaterThan;
    private @Nullable String timeAvailabilityStatusStartedLessThan;

    private GetManagementAgentAvailableHistoriesResult() {}
    /**
     * @return The list of availability_histories.
     * 
     */
    public List<GetManagementAgentAvailableHistoriesAvailabilityHistory> availabilityHistories() {
        return this.availabilityHistories;
    }
    public List<GetManagementAgentAvailableHistoriesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return agent identifier
     * 
     */
    public String managementAgentId() {
        return this.managementAgentId;
    }
    public Optional<String> timeAvailabilityStatusEndedGreaterThan() {
        return Optional.ofNullable(this.timeAvailabilityStatusEndedGreaterThan);
    }
    public Optional<String> timeAvailabilityStatusStartedLessThan() {
        return Optional.ofNullable(this.timeAvailabilityStatusStartedLessThan);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagementAgentAvailableHistoriesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetManagementAgentAvailableHistoriesAvailabilityHistory> availabilityHistories;
        private @Nullable List<GetManagementAgentAvailableHistoriesFilter> filters;
        private String id;
        private String managementAgentId;
        private @Nullable String timeAvailabilityStatusEndedGreaterThan;
        private @Nullable String timeAvailabilityStatusStartedLessThan;
        public Builder() {}
        public Builder(GetManagementAgentAvailableHistoriesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityHistories = defaults.availabilityHistories;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.managementAgentId = defaults.managementAgentId;
    	      this.timeAvailabilityStatusEndedGreaterThan = defaults.timeAvailabilityStatusEndedGreaterThan;
    	      this.timeAvailabilityStatusStartedLessThan = defaults.timeAvailabilityStatusStartedLessThan;
        }

        @CustomType.Setter
        public Builder availabilityHistories(List<GetManagementAgentAvailableHistoriesAvailabilityHistory> availabilityHistories) {
            if (availabilityHistories == null) {
              throw new MissingRequiredPropertyException("GetManagementAgentAvailableHistoriesResult", "availabilityHistories");
            }
            this.availabilityHistories = availabilityHistories;
            return this;
        }
        public Builder availabilityHistories(GetManagementAgentAvailableHistoriesAvailabilityHistory... availabilityHistories) {
            return availabilityHistories(List.of(availabilityHistories));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetManagementAgentAvailableHistoriesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetManagementAgentAvailableHistoriesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetManagementAgentAvailableHistoriesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder managementAgentId(String managementAgentId) {
            if (managementAgentId == null) {
              throw new MissingRequiredPropertyException("GetManagementAgentAvailableHistoriesResult", "managementAgentId");
            }
            this.managementAgentId = managementAgentId;
            return this;
        }
        @CustomType.Setter
        public Builder timeAvailabilityStatusEndedGreaterThan(@Nullable String timeAvailabilityStatusEndedGreaterThan) {

            this.timeAvailabilityStatusEndedGreaterThan = timeAvailabilityStatusEndedGreaterThan;
            return this;
        }
        @CustomType.Setter
        public Builder timeAvailabilityStatusStartedLessThan(@Nullable String timeAvailabilityStatusStartedLessThan) {

            this.timeAvailabilityStatusStartedLessThan = timeAvailabilityStatusStartedLessThan;
            return this;
        }
        public GetManagementAgentAvailableHistoriesResult build() {
            final var _resultValue = new GetManagementAgentAvailableHistoriesResult();
            _resultValue.availabilityHistories = availabilityHistories;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.managementAgentId = managementAgentId;
            _resultValue.timeAvailabilityStatusEndedGreaterThan = timeAvailabilityStatusEndedGreaterThan;
            _resultValue.timeAvailabilityStatusStartedLessThan = timeAvailabilityStatusStartedLessThan;
            return _resultValue;
        }
    }
}
