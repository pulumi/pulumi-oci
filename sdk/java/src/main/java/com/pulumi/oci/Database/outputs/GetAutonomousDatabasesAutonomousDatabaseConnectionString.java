// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.outputs.GetAutonomousDatabasesAutonomousDatabaseConnectionStringProfile;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetAutonomousDatabasesAutonomousDatabaseConnectionString {
    /**
     * @return Returns all connection strings that can be used to connect to the Autonomous Database. For more information, please see [Predefined Database Service Names for Autonomous Transaction Processing](https://docs.oracle.com/en/cloud/paas/atp-cloud/atpug/connect-predefined.html#GUID-9747539B-FD46-44F1-8FF8-F5AC650F15BE)
     * 
     */
    private Map<String,String> allConnectionStrings;
    /**
     * @return The database service provides the least level of resources to each SQL statement, but supports the most number of concurrent SQL statements.
     * 
     */
    private String dedicated;
    /**
     * @return The High database service provides the highest level of resources to each SQL statement resulting in the highest performance, but supports the fewest number of concurrent SQL statements.
     * 
     */
    private String high;
    /**
     * @return The Low database service provides the least level of resources to each SQL statement, but supports the most number of concurrent SQL statements.
     * 
     */
    private String low;
    /**
     * @return The Medium database service provides a lower level of resources to each SQL statement potentially resulting a lower level of performance, but supports more concurrent SQL statements.
     * 
     */
    private String medium;
    /**
     * @return A list of connection string profiles to allow clients to group, filter and select connection string values based on structured metadata.
     * 
     */
    private List<GetAutonomousDatabasesAutonomousDatabaseConnectionStringProfile> profiles;

    private GetAutonomousDatabasesAutonomousDatabaseConnectionString() {}
    /**
     * @return Returns all connection strings that can be used to connect to the Autonomous Database. For more information, please see [Predefined Database Service Names for Autonomous Transaction Processing](https://docs.oracle.com/en/cloud/paas/atp-cloud/atpug/connect-predefined.html#GUID-9747539B-FD46-44F1-8FF8-F5AC650F15BE)
     * 
     */
    public Map<String,String> allConnectionStrings() {
        return this.allConnectionStrings;
    }
    /**
     * @return The database service provides the least level of resources to each SQL statement, but supports the most number of concurrent SQL statements.
     * 
     */
    public String dedicated() {
        return this.dedicated;
    }
    /**
     * @return The High database service provides the highest level of resources to each SQL statement resulting in the highest performance, but supports the fewest number of concurrent SQL statements.
     * 
     */
    public String high() {
        return this.high;
    }
    /**
     * @return The Low database service provides the least level of resources to each SQL statement, but supports the most number of concurrent SQL statements.
     * 
     */
    public String low() {
        return this.low;
    }
    /**
     * @return The Medium database service provides a lower level of resources to each SQL statement potentially resulting a lower level of performance, but supports more concurrent SQL statements.
     * 
     */
    public String medium() {
        return this.medium;
    }
    /**
     * @return A list of connection string profiles to allow clients to group, filter and select connection string values based on structured metadata.
     * 
     */
    public List<GetAutonomousDatabasesAutonomousDatabaseConnectionStringProfile> profiles() {
        return this.profiles;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutonomousDatabasesAutonomousDatabaseConnectionString defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Map<String,String> allConnectionStrings;
        private String dedicated;
        private String high;
        private String low;
        private String medium;
        private List<GetAutonomousDatabasesAutonomousDatabaseConnectionStringProfile> profiles;
        public Builder() {}
        public Builder(GetAutonomousDatabasesAutonomousDatabaseConnectionString defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.allConnectionStrings = defaults.allConnectionStrings;
    	      this.dedicated = defaults.dedicated;
    	      this.high = defaults.high;
    	      this.low = defaults.low;
    	      this.medium = defaults.medium;
    	      this.profiles = defaults.profiles;
        }

        @CustomType.Setter
        public Builder allConnectionStrings(Map<String,String> allConnectionStrings) {
            if (allConnectionStrings == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesAutonomousDatabaseConnectionString", "allConnectionStrings");
            }
            this.allConnectionStrings = allConnectionStrings;
            return this;
        }
        @CustomType.Setter
        public Builder dedicated(String dedicated) {
            if (dedicated == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesAutonomousDatabaseConnectionString", "dedicated");
            }
            this.dedicated = dedicated;
            return this;
        }
        @CustomType.Setter
        public Builder high(String high) {
            if (high == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesAutonomousDatabaseConnectionString", "high");
            }
            this.high = high;
            return this;
        }
        @CustomType.Setter
        public Builder low(String low) {
            if (low == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesAutonomousDatabaseConnectionString", "low");
            }
            this.low = low;
            return this;
        }
        @CustomType.Setter
        public Builder medium(String medium) {
            if (medium == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesAutonomousDatabaseConnectionString", "medium");
            }
            this.medium = medium;
            return this;
        }
        @CustomType.Setter
        public Builder profiles(List<GetAutonomousDatabasesAutonomousDatabaseConnectionStringProfile> profiles) {
            if (profiles == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesAutonomousDatabaseConnectionString", "profiles");
            }
            this.profiles = profiles;
            return this;
        }
        public Builder profiles(GetAutonomousDatabasesAutonomousDatabaseConnectionStringProfile... profiles) {
            return profiles(List.of(profiles));
        }
        public GetAutonomousDatabasesAutonomousDatabaseConnectionString build() {
            final var _resultValue = new GetAutonomousDatabasesAutonomousDatabaseConnectionString();
            _resultValue.allConnectionStrings = allConnectionStrings;
            _resultValue.dedicated = dedicated;
            _resultValue.high = high;
            _resultValue.low = low;
            _resultValue.medium = medium;
            _resultValue.profiles = profiles;
            return _resultValue;
        }
    }
}
