// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.GoldenGate.outputs.GetDeploymentUpgradesDeploymentUpgradeCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeploymentUpgradesDeploymentUpgradeCollection {
    private List<GetDeploymentUpgradesDeploymentUpgradeCollectionItem> items;

    private GetDeploymentUpgradesDeploymentUpgradeCollection() {}
    public List<GetDeploymentUpgradesDeploymentUpgradeCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentUpgradesDeploymentUpgradeCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDeploymentUpgradesDeploymentUpgradeCollectionItem> items;
        public Builder() {}
        public Builder(GetDeploymentUpgradesDeploymentUpgradeCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetDeploymentUpgradesDeploymentUpgradeCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetDeploymentUpgradesDeploymentUpgradeCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetDeploymentUpgradesDeploymentUpgradeCollectionItem... items) {
            return items(List.of(items));
        }
        public GetDeploymentUpgradesDeploymentUpgradeCollection build() {
            final var _resultValue = new GetDeploymentUpgradesDeploymentUpgradeCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
