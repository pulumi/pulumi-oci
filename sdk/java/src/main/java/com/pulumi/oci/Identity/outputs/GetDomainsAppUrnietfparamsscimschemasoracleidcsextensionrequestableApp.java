// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.util.Objects;

@CustomType
public final class GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionrequestableApp {
    /**
     * @return Flag controlling whether resource can be request by user through self service console.
     * 
     */
    private Boolean requestable;

    private GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionrequestableApp() {}
    /**
     * @return Flag controlling whether resource can be request by user through self service console.
     * 
     */
    public Boolean requestable() {
        return this.requestable;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionrequestableApp defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean requestable;
        public Builder() {}
        public Builder(GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionrequestableApp defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.requestable = defaults.requestable;
        }

        @CustomType.Setter
        public Builder requestable(Boolean requestable) {
            this.requestable = Objects.requireNonNull(requestable);
            return this;
        }
        public GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionrequestableApp build() {
            final var o = new GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionrequestableApp();
            o.requestable = requestable;
            return o;
        }
    }
}