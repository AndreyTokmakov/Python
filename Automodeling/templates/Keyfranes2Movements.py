
import json
from typing import Dict, List
from pathlib import Path
import numpy as np
from scipy.spatial.transform import Rotation as Rotation
from copy import deepcopy

"Convert automodelling results to keyframes"
def get_keyframes_from_automodelling_movements(data: Dict, 
                                               auto_modelling_out: Dict = None, 
                                               steps_per_stage: int = 5) -> Dict:
    adj_matrix = np.asarray([
        [-1, 0, 0, 0],
        [0, 0, 1, 0],
        [0, 1, 0, 0],
        [0, 0, 0, 1],
    ])

    matrices_res = {
        'matrices': {}
    }
    quats_and_trans_res = {
        'keyframes': {}
    }

    # Build zero keyframe matrices and movements data
    zero_matrices = {
        'upper': {},
        'lower': {}
    }
    zero_move_data = {  # Выглядят как keyframes из JSON-а от техника
        'upper': {},
        'lower': {}
    }
    modelling_data = data['modellingData']
    upper_tooth_idx = ['11', '12', '13', '14', '15', '16', '17', '18', '21', '22', '23', '24', '25', '26', '27', '28']
    lower_tooth_idx = ['31', '32', '33', '34', '35', '36', '37', '38', '41', '42', '43', '44', '45', '46', '47', '48']

    #print(json.dumps(modelling_data) )

    for tooth_idx, tooth_data in modelling_data.items():
        if tooth_idx in upper_tooth_idx:
            jaw_type = 'upper'
        elif tooth_idx in lower_tooth_idx:
            jaw_type = 'lower'

        matrix = np.eye(4)
        origin = np.asarray(tooth_data['origin'], dtype=np.float64)
        matrix[:3, 3] = origin.T

        movements = {
            "TIP": "0.0",
            "Torque": "0.0",
            "Rotation": "0.0",
            "Mesial-distal": "0.0",
            "Buccal-lingual": "0.0",
            "Extrusion-intrusion": "0.0"
        }
        zero_matrices[jaw_type][tooth_idx] = {
            "matrix": matrix.T.flatten().tolist(), # Transpositioned 'origin' matrix from 'modellingData' as LIST
            "movements": movements,
            "anchor_index": 0,
            "rotation_order": "XYZ"
        }

        quat = [0, 0, 0, 1]
        quaternions = [quat] * 3   # --> [[0, 0, 0, 1], [0, 0, 0, 1], [0, 0, 0, 1]]
        translation = [0] * 3      # --> [0, 0, 0]
        zero_move_data[jaw_type][tooth_idx] = {
            "quaternions": quaternions,
            "translation": translation,
            "quaternion_index": 0
        }

    if auto_modelling_out is not None:
        step_matrices = auto_modelling_out['step_matrices']
    else:
        step_matrices = data['step_matrices']

    # print(zero_matrices)

    for jaw_type, jaw_data in step_matrices.items():
        # Get zero keyframe (get from teeht.serialization or modelingData)

        kf_matrices = zero_matrices[jaw_type]   
        kf_move_data = zero_move_data[jaw_type]   # судя по всему тут что-то типа keyframes для челюсти upper/lower - но пустые
        jaw_res_matrices = [deepcopy(kf_matrices)]
        jaw_res_move_data = [deepcopy(kf_move_data)]
        step_id = 0
        stage_step = 0

        for step in jaw_data:
            print(f'======================================================= step ({jaw_type}), step_id = {step_id} =======================================================')     # ****** PRINT ******* 
            if stage_step >= steps_per_stage:
                stage_step = 0
                # Write KF data to result if stage is ended
                jaw_res_matrices.append(deepcopy(kf_matrices))
                jaw_res_move_data.append(deepcopy(kf_move_data))

            for tooth_id, tooth_step_data in step.items():
                try:
                    int(tooth_id)
                except ValueError:
                    continue

                # Get current KF matrice and movement data for tooth
                kf_matrix = np.asarray(kf_matrices[tooth_id]['matrix'], dtype=np.float64).reshape((4, 4)).T
                kf_quat_id = kf_move_data[tooth_id]['quaternion_index']
                kf_rotations = [Rotation.from_quat(quat) for quat in kf_move_data[tooth_id]['quaternions']]
                kf_translation = np.asarray(kf_move_data[tooth_id]['translation'], dtype=np.float64)

                # Get step matrice from step_matrices for tooth
                current_step_matrix = np.asarray(tooth_step_data['matrix'], dtype=np.float64).reshape((4, 4))
                if auto_modelling_out is None:
                    current_step_matrix = current_step_matrix.T
           
                # Move matrice
                if step_id == 0:
                    mov_matrix = current_step_matrix
                else: # Calculate movement matrice and apply it to cur KF
                    prev_step = step_matrices[jaw_type][step_id-1]
                    prev_step_matrix = np.asarray(prev_step[tooth_id]['matrix'], dtype=np.float64).reshape((4, 4))
                    if auto_modelling_out is None:
                        prev_step_matrix = prev_step_matrix.T
                    mov_matrix = current_step_matrix @ np.linalg.inv(prev_step_matrix)

                if auto_modelling_out is not None:
                    new_matrix = adj_matrix @ kf_matrix
                    new_matrix = mov_matrix @ new_matrix
                    new_matrix = adj_matrix @ new_matrix
                    mov_matrix = new_matrix @ np.linalg.inv(kf_matrix)
                else:
                    new_matrix = mov_matrix @ kf_matrix

                first_anchor = kf_matrix[:3, 3].T
                first_anchor_matrix = np.eye(4)
                first_anchor_matrix[:3, 3] = first_anchor.T
                first_anchor_matrix_inv = np.eye(4)
                first_anchor_matrix_inv[:3, 3] = -first_anchor.T
                R = first_anchor_matrix_inv @ mov_matrix @ first_anchor_matrix
                mov_rotation = Rotation.from_matrix(R[:3, :3])
                mov_translation = R[:3, 3].T

                new_quat_id = kf_quat_id
                new_rotations = kf_rotations
                new_rotations[new_quat_id] = kf_rotations[new_quat_id] * mov_rotation
                new_translation = kf_translation + mov_translation

                # Update current KF matrice and movement data
                kf_matrices[tooth_id]['matrix'] = new_matrix.T.flatten().tolist()
                kf_move_data[tooth_id]['quaternion_index'] = new_quat_id
                kf_move_data[tooth_id]['quaternions'] = [rotation.as_quat().tolist() for rotation in new_rotations]
                kf_move_data[tooth_id]['translation'] = new_translation.tolist()
            step_id = step_id + 1
            stage_step = stage_step + 1

        # Write last KF data
        jaw_res_matrices.append(deepcopy(kf_matrices))
        jaw_res_move_data.append(deepcopy(kf_move_data))
        matrices_res['matrices'][jaw_type] = jaw_res_matrices
        quats_and_trans_res['keyframes'][jaw_type] = jaw_res_move_data

    result = {
        "matrices": matrices_res['matrices'],
        "keyframes": quats_and_trans_res['keyframes']
    }
    # return result

    data["matrices"] = matrices_res['matrices']
    data["keyframes"] = quats_and_trans_res['keyframes']
    return data



if __name__ == '__main__':

    case_id = 2620
    plan_json_path = f"/home/andtokm/Projects/data/cases/{case_id}/Plan.json"
    step_matrices  = f"/home/andtokm/Projects/data/cases/{case_id}/automodeling/out/transformation_{case_id}_final_res.json"
    dest_file      = f"/home/andtokm/Projects/data/cases/{case_id}/Plan_AutoModeling.json"

    origPlanJson: Dict  = dict()
    with open(plan_json_path) as json_file:
        origPlanJson: Dict = json.load(json_file)

    spepMatricesJson: Dict  = dict()
    with open(step_matrices) as json_file:
        spepMatricesJson: Dict = json.load(json_file)

    result = get_keyframes_from_automodelling_movements(origPlanJson, spepMatricesJson)
    
    with open(dest_file, 'w') as dest_file:
        jsonOutput = json.dumps(result) 
        dest_file.write(jsonOutput)
