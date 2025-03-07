// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAutonomousDatabaseInstanceWalletManagementResult {
    /**
     * @return The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    private String autonomousDatabaseId;
    private Integer gracePeriod;
    private String id;
    /**
     * @return Indicates whether to rotate the wallet or not. If `false`, the wallet will not be rotated. The default is `false`.
     * 
     */
    private Boolean shouldRotate;
    /**
     * @return The current lifecycle state of the Autonomous Database wallet.
     * 
     */
    private String state;
    /**
     * @return The date and time the wallet was last rotated.
     * 
     */
    private String timeRotated;

    private GetAutonomousDatabaseInstanceWalletManagementResult() {}
    /**
     * @return The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String autonomousDatabaseId() {
        return this.autonomousDatabaseId;
    }
    public Integer gracePeriod() {
        return this.gracePeriod;
    }
    public String id() {
        return this.id;
    }
    /**
     * @return Indicates whether to rotate the wallet or not. If `false`, the wallet will not be rotated. The default is `false`.
     * 
     */
    public Boolean shouldRotate() {
        return this.shouldRotate;
    }
    /**
     * @return The current lifecycle state of the Autonomous Database wallet.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the wallet was last rotated.
     * 
     */
    public String timeRotated() {
        return this.timeRotated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutonomousDatabaseInstanceWalletManagementResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String autonomousDatabaseId;
        private Integer gracePeriod;
        private String id;
        private Boolean shouldRotate;
        private String state;
        private String timeRotated;
        public Builder() {}
        public Builder(GetAutonomousDatabaseInstanceWalletManagementResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.autonomousDatabaseId = defaults.autonomousDatabaseId;
    	      this.gracePeriod = defaults.gracePeriod;
    	      this.id = defaults.id;
    	      this.shouldRotate = defaults.shouldRotate;
    	      this.state = defaults.state;
    	      this.timeRotated = defaults.timeRotated;
        }

        @CustomType.Setter
        public Builder autonomousDatabaseId(String autonomousDatabaseId) {
            if (autonomousDatabaseId == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseInstanceWalletManagementResult", "autonomousDatabaseId");
            }
            this.autonomousDatabaseId = autonomousDatabaseId;
            return this;
        }
        @CustomType.Setter
        public Builder gracePeriod(Integer gracePeriod) {
            if (gracePeriod == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseInstanceWalletManagementResult", "gracePeriod");
            }
            this.gracePeriod = gracePeriod;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseInstanceWalletManagementResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder shouldRotate(Boolean shouldRotate) {
            if (shouldRotate == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseInstanceWalletManagementResult", "shouldRotate");
            }
            this.shouldRotate = shouldRotate;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseInstanceWalletManagementResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeRotated(String timeRotated) {
            if (timeRotated == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabaseInstanceWalletManagementResult", "timeRotated");
            }
            this.timeRotated = timeRotated;
            return this;
        }
        public GetAutonomousDatabaseInstanceWalletManagementResult build() {
            final var _resultValue = new GetAutonomousDatabaseInstanceWalletManagementResult();
            _resultValue.autonomousDatabaseId = autonomousDatabaseId;
            _resultValue.gracePeriod = gracePeriod;
            _resultValue.id = id;
            _resultValue.shouldRotate = shouldRotate;
            _resultValue.state = state;
            _resultValue.timeRotated = timeRotated;
            return _resultValue;
        }
    }
}
