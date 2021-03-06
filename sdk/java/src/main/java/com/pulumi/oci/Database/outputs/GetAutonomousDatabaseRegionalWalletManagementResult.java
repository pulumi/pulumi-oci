// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAutonomousDatabaseRegionalWalletManagementResult {
    private final String id;
    private final Boolean shouldRotate;
    /**
     * @return The current lifecycle state of the Autonomous Database wallet.
     * 
     */
    private final String state;
    /**
     * @return The date and time the wallet was last rotated.
     * 
     */
    private final String timeRotated;

    @CustomType.Constructor
    private GetAutonomousDatabaseRegionalWalletManagementResult(
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("shouldRotate") Boolean shouldRotate,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("timeRotated") String timeRotated) {
        this.id = id;
        this.shouldRotate = shouldRotate;
        this.state = state;
        this.timeRotated = timeRotated;
    }

    public String id() {
        return this.id;
    }
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

    public static Builder builder(GetAutonomousDatabaseRegionalWalletManagementResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String id;
        private Boolean shouldRotate;
        private String state;
        private String timeRotated;

        public Builder() {
    	      // Empty
        }

        public Builder(GetAutonomousDatabaseRegionalWalletManagementResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
    	      this.shouldRotate = defaults.shouldRotate;
    	      this.state = defaults.state;
    	      this.timeRotated = defaults.timeRotated;
        }

        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder shouldRotate(Boolean shouldRotate) {
            this.shouldRotate = Objects.requireNonNull(shouldRotate);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder timeRotated(String timeRotated) {
            this.timeRotated = Objects.requireNonNull(timeRotated);
            return this;
        }        public GetAutonomousDatabaseRegionalWalletManagementResult build() {
            return new GetAutonomousDatabaseRegionalWalletManagementResult(id, shouldRotate, state, timeRotated);
        }
    }
}
