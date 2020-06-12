//
//  AlertController.swift
//  SDHome
//


import UIKit

class FlowViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        print("Network Monitoring page loaded")
    }

    @IBAction func ReturnBtn(_ sender: Any) {
        self.performSegue(withIdentifier: "FlowReturn", sender: self)
    }
}
