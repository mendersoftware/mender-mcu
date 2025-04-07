## Flash wear estimation

- $N$: Number of deployments during the lifetime of a device.
- $F$: Probability of failure during a deployment.
- $W$: Maximum number of state transitions, defined by `MENDER_MAX_STATE_DATA_STORE_COUNT`.
- $B$: Number of writes for a successful deployment.
- $K$: Total number of writes to the flash.

We write to the flash in two places:
1. if no authentication keys are provided by the user, the client will generate authentication keys and write them to the store
2. during a deployment to keep track of the deployment data, the Artifact being installed and the deployment logs

Most of the flash wear will occur during a deployment. The deployment data, which -- amongst others -- contains the current state during
a deployment, is written between each state transition. This is what allows Mender to be robust and do atomic deployments. Unless
`MENDER_DEPLOYMENT_LOGS` is disabled, we write the deployment logs to the flash; these are error or warning logs that have occurred during
a deployment and that are sent to the Mender server on failed deployments for further diagnostics and troubleshooting.

On a successful deployment we update the local provides database with the meta-data from the Artifact that was installed, combining
provides, Artifact name and clears provides.

A successful deployment using the zephyr-image update module will go through 6 state transitions and write the provides and the Artifact
name to the flash. This results in around $K = 6+2$ writes.

Based on numbers seen in production, we can expect a 5% failure rate for deployments. If we factor in the estimated failure percentage, we
can roughly estimate the expected amount of writes during the lifetime of a device:

$K = N \times ( (W \times F ) + (B \times (1 - F)))$

If we plot in the following values:
- $N = 100$
- $F = 0.05$
- $W = 28$ (the default value of `MENDER_MAX_STATE_DATA_STORE_COUNT`)
- $B = 8$ (the amount of writes for a successful deployment with zephyr-image update module)

we get an estimated $K = 900$ writes to the flash during the lifetime of a device.

The equation aims at creating an upper estimate; estimating the exact number of writes during a deployment is next to impossible due to the
unpredictability of the errors and warnings that may occur. However, we can still be fairly sure that the number of writes will be lower than
the estimate, as its based on the maximum number of state transitions during a deployment. The equation does _not_ take the deployment logs
directly into account, but considering the low probability of any failed deployment reaching the maximum state count, we can be rather confident
in the fact that the total number of writes will fall within the estimate.

The flash wear, including the number of erased sectors, physical sectors used, wear leveling, and more, is influenced by the low-level
implementation of the API, such as NVS in Zephyr. The estimate we provide reflects expected writes, but actual wear is affected by various
device-specific factors beyond our control.
